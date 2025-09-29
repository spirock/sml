# Strategy: estimate an appropriate contamination from ground-truth (when available)
# 1) Train a preliminary IsolationForest with contamination='auto' on X_train to obtain scores
# 2) If y_true exists, find the threshold that maximizes F1 over a quantile grid
# 3) Estimate contamination as the fraction of examples below that threshold
# 4) Train the final IsolationForest with the estimated contamination
# If no y_true is available, fall back to a safe default ('auto' or DEFAULT_PERCENTILE)

# Preliminary model to obtain scores for threshold estimation
prelim_model = IsolationForest(contamination='auto', random_state=42)
prelim_model.fit(X_train)
prelim_scores = prelim_model.decision_function(X_full)

estimated_contamination = None
if 'y_true' in locals() and y_true is not None:
    # search for best threshold using existing y_true (same logic as below)
    quantiles = np.linspace(0.80, 0.995, 60)
    grid = np.quantile(prelim_scores, quantiles)
    grid = np.unique(grid)
    evals = []
    for t in grid:
        y_pred_bin = (prelim_scores < t).astype(int)
        f1 = f1_score(y_true, y_pred_bin, zero_division=0)
        evals.append((t, f1))
    if evals:
        best_thr_prelim, best_f1_prelim = max(evals, key=lambda x: x[1])
        estimated_contamination = float((prelim_scores < best_thr_prelim).mean())
        print(f"[TM] 🎯 Estimación de contaminación basada en ground-truth: {estimated_contamination:.6f} (F1={best_f1_prelim:.3f})")

# Fallbacks: if no estimate, use 'auto' (model decides) or a small default
if estimated_contamination is None:
    # If we couldn't estimate from ground truth, use 'auto' for final model
    final_contamination = 'auto'
    print("[TM] ⚠ No se pudo estimar contaminación desde ground-truth. Usando 'auto' para IsolationForest.")
else:
    # Ensure contamination is within sensible bounds
    final_contamination = max(min(estimated_contamination, 0.5), 1e-6)
    print(f"[TM] ℹ︎ Contaminación final aplicada al entrenamiento: {final_contamination:.6f}")

# Train final model on the (normal) training set
model = IsolationForest(contamination=final_contamination, random_state=42)
model.fit(X_train)
