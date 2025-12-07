import math

def perplexity_like(length, unique):
    if length == 0:
        return 0.0
    r = unique / length
    return max(0.0, min(100.0, (1.0 - r) * 100.0))

def burstiness(sentences):
    if not sentences:
        return 0.0
    ls = [len(s) for s in sentences]
    mean = sum(ls) / len(ls)
    var = sum((x - mean) ** 2 for x in ls) / len(ls)
    std = math.sqrt(var)
    return max(0.0, min(100.0, std))

def text_stats(text):
    if not text:
        return {"perplexity": 0.0, "burstiness": 0.0}
    words = [w for w in text.split() if w]
    unique = len(set(words))
    ppl = perplexity_like(len(words), unique)
    sents = [s for s in text.split("\n") if s]
    bur = burstiness(sents)
    return {"perplexity": ppl, "burstiness": bur}
