"""
D03 Log ML Trainer
"""
import json, glob, os, re, pickle, numpy as np
from pathlib import Path
from datetime import datetime

LOG_DIR = Path(__file__).parent.parent / "output" / "scenario_logs"
MODEL_DIR = Path(__file__).parent.parent / "output" / "trained_models"
MODEL_DIR.mkdir(exist_ok=True)

class LogFeatureExtractor:
    MALICIOUS_KEYWORDS = {
        "ids": ["C2","Beacon","EternalBlue","Sliver","CobaltStrike","Emotet","MALWARE","EXPLOIT","CNC"],
        "email": ["PHISH","ceo-phish","fake-bill","micosoft-secure"],
        "endpoint": ["CreateRemoteThread","lsass.exe","outbound to 203.","outbound to 45."],
        "dns": ["c2-beacon","exfil-dns","phish-login","emotet-malware"],
        "auth": ["EventID=4625","FAILED","UnknownUser"],
        "firewall": ["DENY",":445","-> 172.16"],
        "proxy": ["pastebin","webhook","ngrok"],
        "siem": ["CRITICAL","HIGH","C2 Beacon","Lateral Movement"],
        "netflow": [],
    }
    def __init__(self):
        sources = ["auth","dns","email","endpoint","firewall","ids","netflow","proxy","siem"]
        self.feature_names = []
        for s in sources:
            self.feature_names.append(f"{s}_events")
            self.feature_names.append(f"{s}_malicious")
        self.feature_names += ["total_events","malicious_ratio","unique_ips","unique_ports",
                               "critical_alerts","high_alerts","suspicious_dns","failed_auth",
                               "phish_count","ids_detect_ratio","anomaly_score"]
        self.n_features = len(self.feature_names)

    def extract_features(self, logs):
        sources = ["auth","dns","email","endpoint","firewall","ids","netflow","proxy","siem"]
        feats = []; total_events = total_mal = 0; ips = set(); ports = set()
        for s in sources:
            lines = logs.get(s,[]); n = len(lines); total_events += n
            mal = sum(1 for l in lines for kw in self.MALICIOUS_KEYWORDS.get(s,[]) if kw.upper() in l.upper())
            total_mal += mal; feats.extend([n, mal])
            for l in lines:
                found_ips = re.findall(r"\d+\.\d+\.\d+\.\d+", l); ips.update(found_ips[:1])
                found_ports = re.findall(r":(\d+)", l); ports.update(found_ports[-1:] if found_ports else [])
        feats.extend([total_events, total_mal/max(total_events,1), len(ips), len(ports)])
        siem_lines = logs.get("siem",[])
        feats.extend([sum(1 for l in siem_lines if "CRITICAL" in l), sum(1 for l in siem_lines if "HIGH" in l)])
        feats.append(sum(1 for l in logs.get("dns",[]) if any(kw in l for kw in self.MALICIOUS_KEYWORDS["dns"])))
        feats.append(sum(1 for l in logs.get("auth",[]) if "FAILED" in l))
        feats.append(sum(1 for l in logs.get("email",[]) if "PHISH" in l))
        ids_lines = logs.get("ids",[]); feats.append(sum(1 for l in ids_lines if "DETECTED" in l)/max(len(ids_lines),1))
        anom = 0.0
        for l in logs.get("netflow",[]):
            m = re.search(r"anomaly_score=(\d+\.?\d*)", l)
            if m: anom = float(m.group(1))
        feats.append(anom)
        while len(feats) < self.n_features: feats.append(0)
        return np.array(feats[:self.n_features], dtype=np.float32)

    def extract_label(self, logs, attack, defense):
        # 3类标签: 0=正常(无攻击), 1=攻击已防御(检测到), 2=攻击未检出(真正攻击)
        has_attack = attack.get("initial_access_success", False) or attack.get("api_driven", False)
        if not has_attack: return 0
        detected = defense.get("attack_detected", False)
        if detected: return 1  # 攻击但已检测
        # 从日志验证是否确实有攻击痕迹
        ids_lines = logs.get("ids",[])
        ids_hits = sum(1 for l in ids_lines if "DETECTED" in l and any(
            kw in l for kw in ["EternalBlue","CobaltStrike","Sliver","C2","Beacon"]))
        if ids_hits >= 2: return 2  # IDS确认的未检出攻击
        siem_critical = any("CRITICAL" in l for l in logs.get("siem",[]))
        if siem_critical: return 1  # SIEM捕获
        return 0 if not has_attack else 1

class SecurityModelTrainer:
    def __init__(self):
        self.extractor = LogFeatureExtractor()
        self.rf_model = self.if_model = None
        self.scaler_mean = self.scaler_std = None
        self.training_stats = {}

    def load_training_data(self, session_dirs):
        X_list, y_list = [], []
        for session_dir in session_dirs:
            sid = os.path.basename(session_dir)
            report_files = list(Path("integration/D03_results").glob(f"d03_sandbox_{sid}.json"))
            sandbox_data = {}
            if report_files:
                with open(report_files[0], encoding="utf-8") as f: sandbox_data = json.load(f)
            for rd in sorted(Path(session_dir).glob("round_*")):
                rn = int(rd.name.split("_")[1]); logs = {}
                for lf in rd.glob("*.log"):
                    with open(lf, encoding="utf-8") as f: logs[lf.stem] = [l.strip() for l in f.readlines() if l.strip()]
                if not logs: continue
                history = sandbox_data.get("history",[])
                att = next((h.get("attack",{}) for h in history if h.get("round")==rn), {})
                dfn = next((h.get("defense",{}) for h in history if h.get("round")==rn), {})
                X_list.append(self.extractor.extract_features(logs))
                y_list.append(self.extractor.extract_label(logs, att, dfn))
        self.X = np.array(X_list); self.y = np.array(y_list)
        return self.X, self.y

    def train(self, X=None, y=None):
        if X is None: X, y = self.X, self.y
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.model_selection import cross_val_score
        self.scaler_mean = X.mean(axis=0); self.scaler_std = X.std(axis=0) + 1e-8
        X_s = (X - self.scaler_mean) / self.scaler_std
        self.rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight="balanced")
        self.rf_model.fit(X_s, y)
        self.if_model = IsolationForest(n_estimators=100, contamination=0.3, random_state=42)
        self.if_model.fit(X_s)
        try:
            cv = cross_val_score(self.rf_model, X_s, y, cv=min(5, len(y)//2)); cv_mean = cv.mean()
        except: cv_mean = 0.0
        importances = self.rf_model.feature_importances_
        top = sorted(zip(self.extractor.feature_names, importances), key=lambda x: x[1], reverse=True)[:10]
        self.training_stats = {"n_samples":len(X),"n_attack":int(y.sum()),"n_normal":int(len(y)-y.sum()),
            "cv_accuracy":round(float(cv_mean),4),
            "top_features":[(n,round(float(i),4)) for n,i in top],
            "train_time":datetime.now().isoformat()}
        return self.training_stats

    def predict(self, logs):
        X = self.extractor.extract_features(logs).reshape(1,-1)
        X_s = (X - self.scaler_mean) / self.scaler_std
        rf_pred = int(self.rf_model.predict(X_s)[0])
        rf_proba = float(self.rf_model.predict_proba(X_s)[0][1])
        if_pred = int(self.if_model.predict(X_s)[0] == -1)
        if_score = float(self.if_model.decision_function(X_s)[0])
        return {"rf_attack_prob":round(rf_proba,4),"rf_is_attack":bool(rf_pred),
                "if_is_anomaly":bool(if_pred),"if_anomaly_score":round(if_score,4),
                "verdict":"malicious" if (rf_proba>0.6 or if_pred) else "benign"}

    def save(self, name="default"):
        path = MODEL_DIR / name; path.mkdir(exist_ok=True)
        with open(path/"rf_model.pkl","wb") as f: pickle.dump(self.rf_model,f)
        with open(path/"if_model.pkl","wb") as f: pickle.dump(self.if_model,f)
        with open(path/"scaler.pkl","wb") as f: pickle.dump((self.scaler_mean,self.scaler_std),f)
        with open(path/"stats.json","w",encoding="utf-8") as f: json.dump(self.training_stats,f,indent=2,ensure_ascii=False)
        return path

if __name__ == "__main__":
    print("="*60)
    print("  D03 Log ML Trainer")
    print("="*60)
    sessions = sorted(glob.glob(str(LOG_DIR/"202*")), key=os.path.getmtime, reverse=True)
    if not sessions:
        print("No training data. Run sandbox first.")
        exit(1)
    print(f"\nTraining sessions: {len(sessions)}")
    trainer = SecurityModelTrainer()
    X, y = trainer.load_training_data(sessions)
    print(f"Data: {len(X)} samples ({int(y.sum())} attack / {int(len(y)-y.sum())} normal)")

    stats = trainer.train()
    print(f"\n=== Training Results ===")
    print(f"CV Accuracy: {stats['cv_accuracy']:.2%}")
    print(f"Top Features:")
    for name, imp in stats["top_features"][:10]:
        print(f"  {name:25s} {imp:.4f} {'#'*int(imp*100)}")

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    trainer.train(X_train, y_train)
    X_st = (X_test - trainer.scaler_mean) / trainer.scaler_std
    y_pred = trainer.rf_model.predict(X_st)

    target_names = ["Normal","Attack-Defended","Attack-Undetected"]
    print(f"\n=== Test Set Evaluation ===")
    print(f"Classes: {dict(zip(target_names, np.bincount(y_test.astype(int))))}")
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    last_round = sorted(Path(sessions[0]).glob("round_*"))[-1]
    test_logs = {}
    for lf in last_round.glob("*.log"):
        with open(lf, encoding="utf-8") as f: test_logs[lf.stem] = [l.strip() for l in f.readlines() if l.strip()]
    X_new = trainer.extractor.extract_features(test_logs).reshape(1,-1)
    X_ns = (X_new - trainer.scaler_mean) / trainer.scaler_std
    pred_class = int(trainer.rf_model.predict(X_ns)[0])
    pred_proba = trainer.rf_model.predict_proba(X_ns)[0]
    print(f"\nDetection on last round: class={pred_class} ({target_names[pred_class]})")
    print(f"  Probabilities: Normal={pred_proba[0]:.3f} Defended={pred_proba[1]:.3f} Undetected={pred_proba[2]:.3f}")

    trainer.save("sandbox_v1")
    print(f"\nModel saved: {MODEL_DIR/'sandbox_v1'}")