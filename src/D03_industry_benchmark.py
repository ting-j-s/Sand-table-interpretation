"""Industry-Standard Security Log ML Benchmark"""
import numpy as np, random, time, os, tempfile, statistics
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest, VotingClassifier
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import *
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.calibration import CalibratedClassifierCV
import D03_four_party_sandbox as base
from D03_security_logger import EnterpriseSecurityLogger
from D03_log_ml_trainer import LogFeatureExtractor

configs = [(0.04,0.45,50,50,100),(0.06,0.55,60,50,200),(0.08,0.60,70,50,300),
           (0.10,0.68,80,50,400),(0.13,0.75,90,50,500),(0.16,0.82,100,50,600),
           (0.20,0.90,110,50,700),(0.25,0.95,120,50,800)]

print('='*65)
print('  INDUSTRY-STANDARD SECURITY LOG ML BENCHMARK')
print(f'  {len(configs)} configs x 50 eps = {len(configs)*50} samples')
print('='*65)

X_list, y_list = [], []
log_dir = tempfile.mkdtemp(prefix='ind_')
t0 = time.time()
for budget, monitoring, n_users, n_eps, seed in configs:
    cfg = base.CONFIG.copy()
    cfg.update({'num_users':n_users,'num_episodes':n_eps,'enable_llm':False,'enable_quantum':False,'seed':seed})
    random.seed(seed); np.random.seed(seed)
    orch = base.FourPartyOrchestrator(cfg)
    orch.company.security_budget_ratio = budget
    orch.company.monitoring_coverage = monitoring
    prev_exfil = 0
    for ep in range(n_eps):
        m = orch.run_episode()
        ep_dir = os.path.join(log_dir, f's{seed}_ep{ep:04d}')
        os.makedirs(ep_dir, exist_ok=True)
        epl = EnterpriseSecurityLogger(log_dir=ep_dir, n_users=n_users)
        epl.generate_episode_logs(orch, m, ep)
        epl.close()
        feat = LogFeatureExtractor.parse_logs(ep_dir, ep)
        X_list.append(LogFeatureExtractor.to_array(feat))
        curr_exfil = m.get('data_exfiltrated_gb',0)
        exfil_delta = curr_exfil - prev_exfil; prev_exfil = curr_exfil
        y_list.append(1 if (exfil_delta>3.0 or m.get('attack_success_rate',0)>0.4 or feat.get('ids_total_alerts',0)>8) else 0)

X = np.array(X_list); y = np.array(y_list)
n_pos = sum(y)
print(f'[1] Data: {len(X)} samples, {n_pos} attacks ({n_pos/len(X)*100:.1f}%), {time.time()-t0:.1f}s')

scaler = RobustScaler(); X_s = scaler.fit_transform(X)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

def evaluate_cv(model, X_s, y, skf, use_decision=False, is_autoencoder=False):
    scores = {'acc':[],'prec':[],'rec':[],'f1':[],'auc':[]}
    for tr, te in skf.split(X_s, y):
        if is_autoencoder:
            X_normal = X_s[tr][y[tr]==0]
            ae = MLPRegressor(hidden_layer_sizes=(128,64,32,64,128),max_iter=600,early_stopping=True,random_state=42)
            ae.fit(X_normal, X_normal)
            X_recon = ae.predict(X_s[te])
            recon_error = np.mean((X_s[te]-X_recon)**2, axis=1)
            train_errors = np.mean((X_normal-ae.predict(X_normal))**2, axis=1)
            threshold = np.percentile(train_errors, 95)
            yp = (recon_error > threshold).astype(int)
            yb = (recon_error - recon_error.min())/(recon_error.max()-recon_error.min()+0.001)
        elif use_decision:
            X_normal = X_s[tr][y[tr]==0]
            model.fit(X_normal)
            yp_raw = model.predict(X_s[te])
            yp = np.where(yp_raw == -1, 1, 0)
            yb = -model.decision_function(X_s[te])
            yb = (yb - yb.min())/(yb.max() - yb.min() + 0.001)
        elif hasattr(model, 'fit'):
            model.fit(X_s[tr], y[tr])
            yp = model.predict(X_s[te])
            yb = model.predict_proba(X_s[te])[:,1]
        scores['acc'].append(accuracy_score(y[te],yp))
        scores['prec'].append(precision_score(y[te],yp,zero_division=0))
        scores['rec'].append(recall_score(y[te],yp,zero_division=0))
        scores['f1'].append(f1_score(y[te],yp,zero_division=0))
        scores['auc'].append(roc_auc_score(y[te],yb))
    return {k:round(np.mean(v),4) for k,v in scores.items()}

print('\n[2] Industry-Standard Model Comparison:')
print(f'  {"Model":<35s} {"Acc":>8s} {"Prec":>8s} {"Rec":>8s} {"F1":>8s} {"AUC":>8s}')
print(f'  {"-"*75}')

results = {}
# Supervised
for name, model in [
    ('RF(400,max_depth=25)', RandomForestClassifier(n_estimators=400,max_depth=25,min_samples_split=3,class_weight='balanced',random_state=42)),
    ('GB(300,depth=8)', GradientBoostingClassifier(n_estimators=300,max_depth=8,learning_rate=0.02,subsample=0.8,random_state=42)),
    ('LogReg(L2,C=0.05)', CalibratedClassifierCV(LogisticRegression(C=0.05,class_weight='balanced',max_iter=2000,random_state=42),cv=3)),
    ('MLP(256/128/64/32)', MLPClassifier(hidden_layer_sizes=(256,128,64,32),max_iter=1500,early_stopping=True,random_state=42,learning_rate='adaptive')),
    ('Ensemble(RF+GB+LR)', VotingClassifier([
        ('rf',RandomForestClassifier(n_estimators=400,max_depth=25,class_weight='balanced',random_state=42)),
        ('gb',GradientBoostingClassifier(n_estimators=300,max_depth=8,learning_rate=0.02,random_state=42)),
        ('lr',LogisticRegression(C=0.05,class_weight='balanced',max_iter=2000,random_state=42))],
        voting='soft',weights=[3,2,1])),
]:
    r = evaluate_cv(model, X_s, y, skf)
    results[name] = r
    print(f'  {name:<35s} {r["acc"]:>8.4f} {r["prec"]:>8.4f} {r["rec"]:>8.4f} {r["f1"]:>8.4f} {r["auc"]:>8.4f}')

# Unsupervised (industry standard for zero-day detection)
for name, model in [
    ('IsolationForest(contam=0.35)', IsolationForest(contamination=0.35,n_estimators=200,random_state=42)),
    ('IsolationForest(auto)', IsolationForest(contamination='auto',n_estimators=200,random_state=42)),
]:
    r = evaluate_cv(model, X_s, y, skf, use_decision=True)
    results[name] = r
    print(f'  {name:<35s} {r["acc"]:>8.4f} {r["prec"]:>8.4f} {r["rec"]:>8.4f} {r["f1"]:>8.4f} {r["auc"]:>8.4f}')

# Autoencoder (DeepLog-inspired)
r = evaluate_cv(None, X_s, y, skf, is_autoencoder=True)
results['Autoencoder(128/64/32)'] = r
print(f'  {"Autoencoder(128/64/32)":<35s} {r["acc"]:>8.4f} {r["prec"]:>8.4f} {r["rec"]:>8.4f} {r["f1"]:>8.4f} {r["auc"]:>8.4f}')

# Semi-supervised (IF pseudo-label + RF)
scores = {'acc':[],'prec':[],'rec':[],'f1':[],'auc':[]}
for tr, te in skf.split(X_s, y):
    if_model = IsolationForest(contamination=0.35, n_estimators=200, random_state=42)
    if_model.fit(X_s[tr][y[tr]==0])
    pseudo_labels = np.where(if_model.predict(X_s[tr]) == -1, 1, 0)
    rf = RandomForestClassifier(n_estimators=300, max_depth=20, class_weight='balanced', random_state=42)
    rf.fit(X_s[tr], pseudo_labels)
    yp = rf.predict(X_s[te])
    yb = rf.predict_proba(X_s[te])[:,1]
    scores['acc'].append(accuracy_score(y[te],yp))
    scores['prec'].append(precision_score(y[te],yp,zero_division=0))
    scores['rec'].append(recall_score(y[te],yp,zero_division=0))
    scores['f1'].append(f1_score(y[te],yp,zero_division=0))
    scores['auc'].append(roc_auc_score(y[te],yb))
r = {k:round(np.mean(v),4) for k,v in scores.items()}
results['IF_pseudo_label+RF'] = r
print(f'  {"IF_pseudo_label+RF":<35s} {r["acc"]:>8.4f} {r["prec"]:>8.4f} {r["rec"]:>8.4f} {r["f1"]:>8.4f} {r["auc"]:>8.4f}')

best = max(results.items(), key=lambda x: x[1]['f1'])
print(f'\n[3] BEST: {best[0]}')
print(f'    F1={best[1]["f1"]:.4f} AUC={best[1]["auc"]:.4f}')
print(f'    Acc={best[1]["acc"]:.4f} Prec={best[1]["prec"]:.4f} Rec={best[1]["rec"]:.4f}')
print(f'    Data: {len(X)} episodes, {n_pos} attacks ({n_pos/len(X)*100:.1f}%)')
print(f'    Methods tested: Supervised(5) + Unsupervised(2) + Autoencoder(1) + Semi-supervised(1)')
