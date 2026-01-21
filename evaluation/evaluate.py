def evaluate(alerts, labels):
    tp = fp = fn = 0

    for alert in alerts:
        if alert["label"] == "malicious":
            if alert["detected"]:
                tp += 1
            else:
                fn += 1
        else:
            if alert["detected"]:
                fp += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    return precision, recall
