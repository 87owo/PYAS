import os, sys, time, json, zlib, array, onnxmltools, multiprocessing
import numpy as np
import pandas as pd
import lightgbm as lgb
import scipy.sparse as sp

from collections import defaultdict
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score

try:
    import orjson
    JSON_LOADS = orjson.loads

except ImportError:
    JSON_LOADS = json.loads

####################################################################################################

JSONL_PATH = "pe_features.jsonl"
MODEL_FILE = "model.txt"
ONNX_FILE = "Pefile_General_T1.onnx"
FEATURE_FILE = "features.json"

TEST_SIZE = 0.0001
RANDOM_SEED = 42
DLL_HASH_DIM = 256
API_HASH_DIM = 1024

EXCLUDE_FEATURES = {
    'label', 'filehash',
}

LGBM_PARAMS = {
    'objective': 'binary',
    'metric': ['binary_logloss', 'auc'],
    'boosting_type': 'gbdt',
    'num_leaves': 128,
    'feature_fraction': 0.8,
    'bagging_fraction': 1.0,
    'bagging_freq': 5,
    'verbose': -1,
    'seed': RANDOM_SEED,
    'n_jobs': -1,
    'max_depth': -1,
    'min_data_in_leaf': 50,
}

####################################################################################################

def analyze_schema(jsonl_path):
    print("[*] Stage 1: Scanning global schema...")
    base_keys = set()
    num_lines = 0

    with open(jsonl_path, 'rb') as f:
        for line in f:
            num_lines += 1

            if not base_keys:
                try:
                    data = JSON_LOADS(line)
                    base_data = data.get('Base')
                    if base_data:
                        base_keys.update(base_data.keys())

                except Exception:
                    pass

    base_schema = sorted([k for k in base_keys if k.lower().strip() not in EXCLUDE_FEATURES])
    dll_schema = [f"DllHash_{i:03d}" for i in range(DLL_HASH_DIM)]
    api_schema = [f"ApiHash_{i:04d}" for i in range(API_HASH_DIM)]
    
    return base_schema, dll_schema, api_schema, num_lines

####################################################################################################

def load_data_efficiently(jsonl_path, base_schema, dll_schema, api_schema, num_lines):
    print(f"[*] Stage 2: Building sparse feature matrix dynamically via Multiprocessing...")
    final_features = base_schema + dll_schema + api_schema

    num_features = len(final_features)
    offset_dll = len(base_schema)
    offset_api = offset_dll + DLL_HASH_DIM

    file_size = os.path.getsize(jsonl_path)
    workers = min(os.cpu_count() or 4, 16)
    chunk_size = file_size // workers
    
    tasks = []
    for i in range(workers):
        start = i * chunk_size
        end = file_size if i == workers - 1 else (i + 1) * chunk_size
        tasks.append((jsonl_path, start, end, base_schema, num_features, offset_dll, offset_api))
        
    with multiprocessing.Pool(workers) as pool:
        results = pool.map(_chunk_worker, tasks)
        
    Xs = [r[0] for r in results if r[0].shape[0] > 0]
    ys = [r[1] for r in results if r[1].shape[0] > 0]
    
    X_final = sp.vstack(Xs, format='csr') if Xs else sp.csr_matrix((0, num_features), dtype=np.float32)
    y_final = np.concatenate(ys) if ys else np.array([], dtype=np.int8)
    
    return X_final, pd.Series(y_final), final_features

def _chunk_worker(args):
    filepath, start_byte, end_byte, base_schema, num_features, offset_dll, offset_api = args
    
    base_idx = {feat: i for i, feat in enumerate(base_schema)}
    base_idx_get = base_idx.get
    
    rows = array.array('i')
    cols = array.array('i')
    vals = array.array('f')
    y_list = array.array('b')
    
    with open(filepath, 'rb') as f:
        if start_byte > 0:
            f.seek(start_byte - 1)
            if f.read(1) != b'\n':
                f.seek(start_byte)
                f.readline()

            else:
                f.seek(start_byte)
        else:
            f.seek(0)
            
        row_idx = 0
        while f.tell() < end_byte:
            line = f.readline()
            if not line:
                break
                
            try:
                data = JSON_LOADS(line)
                y_list.append(data.get('Label', 0))

                base_data = data.get('Base')
                if base_data:
                    for k, v in base_data.items():
                        idx = base_idx_get(k)
                        if idx is not None:
                            val = float(v)
                            if val != 0.0:
                                rows.append(row_idx)
                                cols.append(idx)
                                vals.append(val)

                dll_data = data.get('DLLs')
                if dll_data:
                    for d in dll_data:
                        idx = zlib.crc32(d.encode('utf-8', 'ignore')) % DLL_HASH_DIM
                        rows.append(row_idx)
                        cols.append(offset_dll + idx)
                        vals.append(1.0)

                api_data = data.get('APIs')
                if api_data:
                    for a in api_data:
                        idx = zlib.crc32(a.encode('utf-8', 'ignore')) % API_HASH_DIM
                        rows.append(row_idx)
                        cols.append(offset_api + idx)
                        vals.append(1.0)

                row_idx += 1
            except Exception:
                continue
                
    y_arr = np.frombuffer(y_list, dtype=np.int8)
    np_rows = np.frombuffer(rows, dtype=np.int32)
    np_cols = np.frombuffer(cols, dtype=np.int32)
    np_vals = np.frombuffer(vals, dtype=np.float32)
    
    X_local = sp.csr_matrix((np_vals, (np_rows, np_cols)), shape=(row_idx, num_features), dtype=np.float32)
    
    return X_local, y_arr

####################################################################################################

def _calculate_dynamic_lr(current_iter: int) -> float:
    return max(0.01, 0.1 - (current_iter // 80) * 0.01)

def train_process(X, y, feature_names):
    print(f"[*] Dataset shape: {X.shape}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y)
    
    n_pos = (y_train == 1).sum()
    n_neg = (y_train == 0).sum()
    
    base_weight = n_neg / n_pos if n_pos > 0 else 1.0
    weight_ratio_target = 0.001
    final_pos_weight = base_weight * weight_ratio_target
    
    print(f"[*] Sample distribution: Safe={n_neg}, Malware={n_pos}")
    print(f"[*] Weight correction: Base={base_weight:.4f}, Final={final_pos_weight:.4f}")
    
    train_data = lgb.Dataset(X_train, label=y_train, feature_name=feature_names)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data, feature_name=feature_names)
    
    params = LGBM_PARAMS.copy()
    params['scale_pos_weight'] = final_pos_weight

    print("\n[*] Starting LightGBM training...")
    start_time = time.time()
    
    model = lgb.train(
        params,
        train_data,
        valid_sets=[valid_data],
        num_boost_round=500,
        callbacks=[
            lgb.log_evaluation(period=50),
            lgb.reset_parameter(learning_rate=_calculate_dynamic_lr)
        ]
    )
    
    elapsed = time.time() - start_time
    print(f"\n[+] Training complete, time elapsed {elapsed:.2f} seconds")
    
    return model, X_test, y_test

####################################################################################################

def export_onnx_model(model, feature_names):
    print(f"[*] Exporting ONNX model to {ONNX_FILE}...")
    try:
        initial_type = [('float_input', FloatTensorType([None, len(feature_names)]))]
        onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type)
        onnxmltools.utils.save_model(onnx_model, ONNX_FILE)
        
        with open(FEATURE_FILE, 'w') as f:
            json.dump(feature_names, f)
            
        print(f"[+] ONNX export successful. Feature order saved to {FEATURE_FILE}")
    except Exception as e:
        print(f"[-] ONNX export failed: {e}")

def evaluate_and_save(model, X_test, y_test):
    print("\n------------------- Evaluation Report -------------------\n")
    y_prob = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred = (y_prob > 0.5).astype(int)
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    tp = np.sum((y_test == 1) & (y_pred == 1))
    fn = np.sum((y_test == 1) & (y_pred == 0))
    tn = np.sum((y_test == 0) & (y_pred == 0))
    fp = np.sum((y_test == 0) & (y_pred == 1))
    
    total_malware = tp + fn
    total_safe = tn + fp
    
    detection_rate = (tp / total_malware * 100) if total_malware > 0 else 0.0
    fpr = (fp / total_safe * 100) if total_safe > 0 else 0.0
    
    print(f"Accuracy : {acc:.6f}")
    print(f"ROC AUC  : {auc:.6f}\n")
    
    print(f"True Positive (Class 1) : {detection_rate:.3f}% ({tp}/{total_malware})")
    print(f"False Positive (Class 0) : {fpr:.3f}% ({fp}/{total_safe})")

    print("\n---------------------------------------------------------\n")
    print("[*] Top 20 Features:")
    
    feature_names = model.feature_name()
    importance = model.feature_importance(importance_type='gain')
    feature_imp = pd.DataFrame(sorted(zip(importance, feature_names), reverse=True), columns=['Value', 'Feature'])
    print(feature_imp.head(20).to_string(index=False))
    
    print("\n---------------------------------------------------------\n")
    
    model.save_model(MODEL_FILE)
    print(f"[+] Native model saved to: {os.path.abspath(MODEL_FILE)}")
    
    export_onnx_model(model, feature_names)

####################################################################################################

if __name__ == "__main__":
    multiprocessing.freeze_support()
    print("\n---------------- PE Malware Trainer v4.0 ----------------\n")

    if not os.path.exists(JSONL_PATH):
        print(f"[-] Error: Feature file {JSONL_PATH} not found.")
        sys.exit(1)

    base_schema, dll_schema, api_schema, num_lines = analyze_schema(JSONL_PATH)
    if num_lines == 0:
        print("[-] Error: Feature file is empty.")
        sys.exit(1)

    print(f"[*] Detected Base features: {len(base_schema)}")
    print(f"[*] Hashing DLL features: {len(dll_schema)}")
    print(f"[*] Hashing API features: {len(api_schema)}")

    X, y, final_features = load_data_efficiently(JSONL_PATH, base_schema, dll_schema, api_schema, num_lines)
    
    try:
        model, X_test, y_test = train_process(X, y, final_features)
        evaluate_and_save(model, X_test, y_test)

    except KeyboardInterrupt:
        print("\n\n[-] Training aborted.")
    except Exception as e:
        print(f"\n[-] System exception: {e}")
