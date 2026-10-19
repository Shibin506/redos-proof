# Reads cases (JSON) from the file named in argv, prints each case's leftmost match per input.
import json, re, sys
FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE, "a": re.ASCII}
out = []
for case in json.load(open(sys.argv[1])):
    try:
        flags = 0
        for f in case["flags"]:
            flags |= FLAGS[f]
        r = re.compile(case["pattern"], flags)
    except (re.error, OverflowError, RecursionError) as e:
        out.append({"error": str(e)})
        continue
    spans = []
    for s in case["inputs"]:
        try:
            m = r.search(s)
        except Exception as e:  # CPython's own bugs: reported by the test, not compared
            spans.append({"crash": f"{type(e).__name__}: {e}"})
            continue
        spans.append(list(m.span()) if m else None)
    out.append({"spans": spans})
json.dump(out, sys.stdout)
