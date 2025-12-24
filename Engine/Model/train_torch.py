import os, random
import numpy as np

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import torch.onnx

from torch.utils.data import Dataset, DataLoader
from torchvision import transforms
from PIL import Image
from tqdm import tqdm

####################################################################################################

Image.MAX_IMAGE_PIXELS = None

####################################################################################################

def get_file_list(directory):
    file_paths, labels, class_indices = [], [], {}
    dirs = sorted([d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))])
    for i, cls in enumerate(dirs):
        class_indices[cls] = i
        cls_dir = os.path.join(directory, cls)
        for root, _, files in os.walk(cls_dir):
            for file in files:
                if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif')):
                    file_paths.append(os.path.join(root, file))
                    labels.append(i)
    return file_paths, labels, class_indices

####################################################################################################

class CustomImageDataset(Dataset):
    def __init__(self, file_paths, labels, image_size=(224, 224), color_mode="grayscale"):
        self.file_paths = file_paths
        self.labels = labels
        self.image_size = image_size
        self.color_mode = color_mode
        self.transform = transforms.Resize(image_size)

    def __len__(self):
        return len(self.file_paths)

    def __getitem__(self, idx):
        path = self.file_paths[idx]
        label = self.labels[idx]
        try:
            img = Image.open(path)
            if self.color_mode == "grayscale":
                img = img.convert("L")
            else:
                img = img.convert("RGB")

            img = self.transform(img)
            img_np = np.array(img).astype(np.float32) / 255.0
            img_t = torch.from_numpy(img_np)
            if img_t.ndim == 2:
                img_t = img_t.unsqueeze(0)
            elif img_t.ndim == 3:
                img_t = img_t.permute(2, 0, 1)

        except Exception:
            c = 1 if self.color_mode == "grayscale" else 3
            img_t = torch.zeros((c, *self.image_size), dtype=torch.float32)
        return img_t, label

####################################################################################################

class CoordinateAttention(nn.Module):
    def __init__(self, in_channels, reduction=4):
        super().__init__()
        mip = max(8, in_channels // reduction)
        self.conv1 = nn.Conv2d(in_channels, mip, kernel_size=1, bias=True)
        self.bn1 = nn.BatchNorm2d(mip)
        self.act = nn.Hardswish()
        self.conv_h = nn.Conv2d(mip, in_channels, kernel_size=1, bias=True)
        self.conv_w = nn.Conv2d(mip, in_channels, kernel_size=1, bias=True)

    def forward(self, x):
        identity = x
        n, c, h, w = x.size()
        x_h = torch.mean(x, dim=3, keepdim=True)
        x_w = torch.mean(x, dim=2, keepdim=True)
        
        x_w_t = x_w.permute(0, 1, 3, 2)
        y = torch.cat([x_h, x_w_t], dim=2)
        
        y = self.conv1(y)
        y = self.bn1(y)
        y = self.act(y)

        x_h_prime, x_w_prime = torch.split(y, [h, w], dim=2)
        x_w_prime = x_w_prime.permute(0, 1, 3, 2)
        
        a_h = torch.sigmoid(self.conv_h(x_h_prime))
        a_w = torch.sigmoid(self.conv_w(x_w_prime))
        return identity * a_h * a_w

####################################################################################################

class MixKernelDepthwise(nn.Module):
    def __init__(self, channels, stride):
        super().__init__()
        self.groups = 3
        c_per_group = channels // self.groups
        c_last = channels - c_per_group * (self.groups - 1)
        self.splits = [c_per_group] * (self.groups - 1) + [c_last]
        
        self.conv3x3 = nn.Conv2d(self.splits[0], self.splits[0], 3, stride, 1, groups=self.splits[0], bias=False)
        self.conv1x7 = nn.Conv2d(self.splits[1], self.splits[1], (1, 7), stride, (0, 3), groups=self.splits[1], bias=False)
        self.conv7x1 = nn.Conv2d(self.splits[2], self.splits[2], (7, 1), stride, (3, 0), groups=self.splits[2], bias=False)

    def forward(self, x):
        x_split = torch.split(x, self.splits, dim=1)
        x0 = self.conv3x3(x_split[0])
        x1 = self.conv1x7(x_split[1])
        x2 = self.conv7x1(x_split[2])
        return torch.cat([x0, x1, x2], dim=1)

####################################################################################################

class SEBlock(nn.Module):
    def __init__(self, in_channels, reduction=4):
        super().__init__()
        self.conv1 = nn.Conv2d(in_channels, in_channels // reduction, kernel_size=1, bias=True)
        self.act1 = nn.GELU()
        self.bn1 = nn.BatchNorm2d(in_channels // reduction, eps=1e-3, momentum=0.01)
        self.conv2 = nn.Conv2d(in_channels // reduction, in_channels, kernel_size=1, bias=True)
        self.act2 = nn.Sigmoid()

    def forward(self, x):
        y = self.conv1(x)
        y = self.act1(y)
        y = self.bn1(y)
        y = self.conv2(y)
        y = self.act2(y)
        return x * y

####################################################################################################

class MBConvBlock(nn.Module):
    def __init__(self, in_channels, out_channels, stride, expand_ratio, use_se=True):
        super().__init__()
        self.use_shortcut = (stride == 1 and in_channels == out_channels)
        hidden_dim = int(round(in_channels * expand_ratio))

        layers = []
        if expand_ratio != 1:
            layers.extend([nn.Conv2d(in_channels, hidden_dim, 1, bias=False), nn.BatchNorm2d(hidden_dim), nn.GELU()])

        layers.extend([MixKernelDepthwise(hidden_dim, stride), nn.BatchNorm2d(hidden_dim), nn.GELU()])

        if use_se:
            layers.append(CoordinateAttention(hidden_dim, reduction=4))

        layers.extend([nn.Conv2d(hidden_dim, out_channels, 1, bias=False), nn.BatchNorm2d(out_channels)])
        self.block = nn.Sequential(*layers)

    def forward(self, x):
        if self.use_shortcut:
            return x + self.block(x)
        return self.block(x)

####################################################################################################

class PYASModel(nn.Module):
    def __init__(self, input_shape, num_classes):
        super().__init__()
        c_in = input_shape[-1]
        self.stem = nn.Sequential(nn.Conv2d(c_in, 32, 3, 2, 1, bias=False), nn.BatchNorm2d(32), nn.GELU())

        config = [
            [32,  48, 1, 3],
            [48,  80, 2, 3],
            [80, 112, 2, 3],
            [112, 160, 2, 3],
            [160, 192, 2, 3],
            [192, 256, 2, 3]]

        layers = []
        for in_c, out_c, s, ex in config:
            layers.append(MBConvBlock(in_c, out_c, s, ex))
        self.features = nn.Sequential(*layers)

        self.last_conv = nn.Sequential(nn.Conv2d(256, 512, 1, bias=False), nn.BatchNorm2d(512), nn.GELU(), SEBlock(512, reduction=4))

        self.gap = nn.AdaptiveAvgPool2d(1)
        self.gmp = nn.AdaptiveMaxPool2d(1)

        self.classifier = nn.Sequential(nn.Linear(1024, 256), nn.GELU(), nn.Dropout(0.1), nn.Linear(256, num_classes))

    def forward(self, x):
        x = self.stem(x)
        x = self.features(x)
        x = self.last_conv(x)

        v_gap = torch.flatten(self.gap(x), 1)
        v_gmp = torch.flatten(self.gmp(x), 1)
        feat = torch.cat([v_gap, v_gmp], dim=1) 

        return self.classifier(feat)

####################################################################################################

class ONNXExportWrapper(nn.Module):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, x):
        x = x.permute(0, 3, 1, 2)
        x = self.model(x)
        return F.softmax(x, dim=1)

####################################################################################################

class CategoricalFocalLoss(nn.Module):
    def __init__(self, alpha, gamma=2.0, smoothing=0.1):
        super().__init__()
        self.register_buffer('alpha', torch.tensor(alpha))
        self.gamma = gamma
        self.smoothing = smoothing

    def forward(self, inputs, targets):
        num_classes = inputs.size(-1)
        log_pt = F.log_softmax(inputs, dim=-1)
        
        with torch.no_grad():
            true_dist = torch.zeros_like(log_pt)
            true_dist.fill_(self.smoothing / (num_classes - 1))
            true_dist.scatter_(1, targets.data.unsqueeze(1), 1.0 - self.smoothing)
        
        pt = torch.exp(log_pt)
        focal_weight = self.alpha[targets].unsqueeze(1) * (1 - pt) ** self.gamma
        loss = (-true_dist * log_pt * focal_weight).sum(dim=-1)
        return loss.mean()

def calculate_lr_cosine_sq(epoch, total_epochs, lr_start, lr_end):
    cos_val = 0.5 * (1 + np.cos(epoch / total_epochs * np.pi))
    return lr_end + (lr_start - lr_end) * (cos_val ** 2)

####################################################################################################

def train():
    data_dir = r'.\Image_File_Pefile'
    image_size = (224, 224)
    batch_size = 64
    val_split = 0.025
    total_epochs = 30
    lr_start = 1e-3
    lr_end = 1e-6
    color_mode = "grayscale"

    file_paths, labels, class_indices = get_file_list(data_dir)
    num_classes = len(class_indices)
    sample_counts = {}
    for lbl in labels:
        sample_counts[lbl] = sample_counts.get(lbl, 0) + 1
    total_samples = sum(sample_counts.values())
    class_weights_dict = {k: total_samples / (num_classes * v) for k, v in sample_counts.items()}
    alpha_list = [class_weights_dict[i] for i in range(num_classes)]

    combined = list(zip(file_paths, labels))
    random.shuffle(combined)
    file_paths[:], labels[:] = zip(*combined)

    num_val = int(val_split * len(file_paths))
    train_files, train_labels = file_paths[num_val:], labels[num_val:]
    val_files, val_labels = file_paths[:num_val], labels[:num_val]

    train_ds = CustomImageDataset(train_files, train_labels, image_size, color_mode)
    val_ds = CustomImageDataset(val_files, val_labels, image_size, color_mode)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=4, pin_memory=True, persistent_workers=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=4, pin_memory=True, persistent_workers=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    input_channels = 1 if color_mode == "grayscale" else 3

    model = PYASModel(input_shape=(224, 224, input_channels), num_classes=num_classes)
    if os.path.exists('PYAS_Model_Epoch_0.pth'):
        print("Load model from disk")
        model.load_state_dict(torch.load('PYAS_Model_Epoch_0.pth'))
    else:
        print("Creating a new model")
    model = model.to(device)

    if torch.cuda.device_count() > 1:
        model = nn.DataParallel(model)
    print(f"Total parameters: {sum(p.numel() for p in model.parameters() if p.requires_grad)}")

    optimizer = optim.AdamW(model.parameters(), lr=lr_start, weight_decay=1e-2, amsgrad=True)
    criterion = CategoricalFocalLoss(alpha_list, gamma=2.0).to(device)
    scaler = torch.amp.GradScaler('cuda')

    for epoch in range(total_epochs):
        model.train()

        current_lr = calculate_lr_cosine_sq(epoch, total_epochs, lr_start, lr_end)
        for param_group in optimizer.param_groups:
            param_group['lr'] = current_lr

        running_loss = 0.0
        correct = 0
        total = 0
        
        tp_sum = torch.zeros(num_classes, device=device)
        fp_sum = torch.zeros(num_classes, device=device)
        fn_sum = torch.zeros(num_classes, device=device)

        pbar = tqdm(train_loader, desc=f"Epoch {epoch+1}/{total_epochs}")
        for images, targets in pbar:
            images, targets = images.to(device), targets.to(device)
            current_batch_size = targets.size(0)

            optimizer.zero_grad()
            with torch.amp.autocast('cuda'):
                outputs = model(images)
                loss = criterion(outputs, targets)

            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            running_loss += loss.item() * current_batch_size
            _, predicted = outputs.max(1)
            total += current_batch_size
            correct += predicted.eq(targets).sum().item()

            for i in range(num_classes):
                tp_sum[i] += ((predicted == i) & (targets == i)).sum()
                fp_sum[i] += ((predicted == i) & (targets != i)).sum()
                fn_sum[i] += ((predicted != i) & (targets == i)).sum()

            avg_loss = running_loss / total
            acc = correct / total
            
            prec_cls = tp_sum / (tp_sum + fp_sum + 1e-7)
            rec_cls = tp_sum / (tp_sum + fn_sum + 1e-7)
            f1_cls = 2 * (prec_cls * rec_cls) / (prec_cls + rec_cls + 1e-7)
            
            macro_prec = prec_cls.mean().item()
            macro_f1 = f1_cls.mean().item()
            
            mem = torch.cuda.memory_reserved(device) / (1024**3) if torch.cuda.is_available() else 0

            pbar.set_postfix({
                'loss': f'{avg_loss:.6f}', 
                'acc': f'{acc:.6f}', 
                'prec': f'{macro_prec:.6f}',
                'f1': f'{macro_f1:.6f}',
                'mem': f'{mem:.2f}G',
                'lr': f'{current_lr:.6f}'
            })

        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        v_tp = torch.zeros(num_classes, device=device)
        v_fp = torch.zeros(num_classes, device=device)
        v_fn = torch.zeros(num_classes, device=device)

        val_pbar = tqdm(val_loader, desc=f"Val Epoch {epoch+1}")
        
        with torch.no_grad():
            for images, targets in val_pbar:
                images, targets = images.to(device), targets.to(device)
                current_batch_size = targets.size(0)
                outputs = model(images)
                loss = criterion(outputs, targets)

                val_loss += loss.item() * current_batch_size
                _, predicted = outputs.max(1)
                val_total += current_batch_size
                val_correct += predicted.eq(targets).sum().item()
                
                for i in range(num_classes):
                    v_tp[i] += ((predicted == i) & (targets == i)).sum()
                    v_fp[i] += ((predicted == i) & (targets != i)).sum()
                    v_fn[i] += ((predicted != i) & (targets == i)).sum()
                
                avg_val_loss = val_loss / val_total
                val_acc = val_correct / val_total
                
                v_prec_cls = v_tp / (v_tp + v_fp + 1e-7)
                v_rec_cls = v_tp / (v_tp + v_fn + 1e-7)
                v_f1_cls = 2 * (v_prec_cls * v_rec_cls) / (v_prec_cls + v_rec_cls + 1e-7)
                
                val_macro_prec = v_prec_cls.mean().item()
                val_macro_f1 = v_f1_cls.mean().item()
                
                v_mem = torch.cuda.memory_reserved(device) / (1024**3) if torch.cuda.is_available() else 0

                val_pbar.set_postfix({
                    'v_loss': f'{avg_val_loss:.6f}',
                    'v_acc': f'{val_acc:.6f}',
                    'v_prec': f'{val_macro_prec:.6f}',
                    'v_f1': f'{val_macro_f1:.6f}',
                    'v_mem': f'{v_mem:.2f}G'
                })

        model_to_save = model.module if isinstance(model, nn.DataParallel) else model
        torch.save(model_to_save.state_dict(), f"PYAS_Model_Epoch_{epoch + 1}.pth")
        
        onnx_wrapper = ONNXExportWrapper(model_to_save)
        dummy_input = torch.randn(1, 224, 224, input_channels).to(device)
        
        try:
            torch.onnx.export(
                onnx_wrapper,
                dummy_input,
                f"PYAS_Model_Epoch_{epoch + 1}.onnx",
                export_params=True,
                opset_version=17,
                do_constant_folding=True,
                input_names=['input'],
                output_names=['output'],
                dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}})
        except Exception as e:
            print(f"ONNX Export failed: {e}")

    input('Training Complete')

####################################################################################################

if __name__ == '__main__':
    train()
