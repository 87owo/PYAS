import os, sys, time, sqlite3, re, json
import pandas as pd
import numpy as np
import lightgbm as lgb
import onnxmltools

from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

####################################################################################################

DB_PATH = "pe_features.db"
MODEL_FILE = "model.txt"
ONNX_FILE = "model.onnx"
FEATURE_FILE = "features.json"
TEST_SIZE = 0.0001
RANDOM_SEED = 42

LGBM_PARAMS = {
    'objective': 'binary',
    'metric': ['binary_logloss', 'auc'],
    'boosting_type': 'gbdt',
    'num_leaves': 63,
    'learning_rate': 0.05,
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'verbose': -1,
    'seed': RANDOM_SEED,
    'n_jobs': -1,
    'max_depth': -1,
    'min_data_in_leaf': 20,
    'lambda_l1': 0.1,
    'lambda_l2': 0.1,
}

####################################################################################################

def clean_col_name(name):
    return re.sub(r'[^A-Za-z0-9_]+', '', name)

def get_raw_schema(db_path):
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(PeData)")
        columns = [row[1] for row in cursor.fetchall()]
        exclude = {'label', 'id', 'filename', 'filelength', 'rowid', 'probability', 'predictedlabel', 'score', 'filehash', 'timedatestamp'}
        return [c for c in columns if c.lower().strip() not in exclude]
    except Exception as e:
        print(f"[-] Schema extraction error: {e}")
        return None
    finally:
        conn.close()

####################################################################################################

def load_data(db_path, raw_cols):
    print(f"[*] Connecting to database: {db_path}")
    conn = sqlite3.connect(db_path)
    req_cols = list(set(raw_cols + ['Label']))
    sql = f"SELECT {', '.join(req_cols)} FROM PeData"
    
    try:
        chunks = []
        for chunk in pd.read_sql_query(sql, conn, chunksize=20000):
            label_col = next((c for c in chunk.columns if c.lower().strip() == 'label'), None)
            if not label_col:
                print("[-] Critical Error: Label column not found.")
                return None, None, None

            cols_to_cast = [c for c in chunk.columns if c != label_col]
            chunk[cols_to_cast] = chunk[cols_to_cast].astype(np.float32)
            chunk[label_col] = chunk[label_col].astype(np.int8)
            chunks.append(chunk)

        if not chunks:
            return None, None, None

        df = pd.concat(chunks, ignore_index=True)

        label_col = next((c for c in df.columns if c.lower().strip() == 'label'), None)
        y = df[label_col].astype(int)
        X = df.drop(columns=[label_col], errors='ignore')
        
        valid_features = [c for c in raw_cols if c in X.columns]
        X = X[valid_features].copy()
        
        rename_map = {old: clean_col_name(old) for old in X.columns}
        X = X.rename(columns=rename_map)
        
        if X.columns.duplicated().any():
            print("[-] Warning: Duplicate column names detected after cleaning. Deduplicating...")
            X = X.loc[:, ~X.columns.duplicated()]

        final_features = X.columns.tolist()
        return X, y, final_features
    finally:
        conn.close()

####################################################################################################

def train_process(X, y):
    print(f"[*] Dataset shape: {X.shape}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    
    n_pos = (y_train == 1).sum()
    n_neg = (y_train == 0).sum()
    
    base_weight = n_neg / n_pos if n_pos > 0 else 1.0
    weight_ratio_target = 0.1
    final_pos_weight = base_weight * weight_ratio_target
    
    print(f"[*] Balance Report: Safe={n_neg}, Malware={n_pos}")
    print(f"[*] Weight Config: Base Balanced={base_weight:.4f}, Final Adjusted={final_pos_weight:.4f}")
    
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    params = LGBM_PARAMS.copy()
    params['scale_pos_weight'] = final_pos_weight

    print("\n[*] Starting LightGBM training...")
    start_time = time.time()
    
    model = lgb.train(
        params,
        train_data,
        valid_sets=[valid_data],
        num_boost_round=1000,
        callbacks=[
            lgb.log_evaluation(period=100)
        ]
    )
    
    elapsed = time.time() - start_time
    print(f"\n[+] Training finished in {elapsed:.2f}s")
    
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
            
        print(f"[+] ONNX export success. Features synced to {FEATURE_FILE}")
    except Exception as e:
        print(f"[-] ONNX export failed: {e}")

####################################################################################################

def evaluate_and_save(model, X_test, y_test):
    print("\n------------------- Evaluation Report -------------------\n")
    y_prob = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred = (y_prob > 0.5).astype(int)
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print(f"Accuracy : {acc:.4f}")
    print(f"ROC AUC  : {auc:.4f}")
    print("\n" + classification_report(y_test, y_pred, zero_division=0))

    print("---------------------------------------------------------\n")
    print("[*] Top 20 Features (Importance by Gain):")
    
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
    print("\n---------------- PE Malware Trainer v3.1 ----------------\n")

    if not os.path.exists(DB_PATH):
        print(f"[-] Error: Database {DB_PATH} not found.")
        sys.exit(1)

    raw_schema = get_raw_schema(DB_PATH)
    if not raw_schema:
        print("[-] Error: Could not read schema.")
        sys.exit(1)

    X, y, _ = load_data(DB_PATH, raw_schema)
    if X is None:
        sys.exit(1)

    try:
        model, X_test, y_test = train_process(X, y)
        evaluate_and_save(model, X_test, y_test)
    except KeyboardInterrupt:
        print("\n\n[-] Training interrupted.")
    except Exception as e:
        print(f"\n[-] Critical Error: {e}")
