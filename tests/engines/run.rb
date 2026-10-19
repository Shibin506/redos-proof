# Reads cases (JSON) from the file named in argv, prints each case's leftmost match per input.
# With "anchor_at": n, the match must start exactly at n (\G), instead of searching from the left.
require "json"
$VERBOSE = nil
Regexp.timeout = 1.0 # random patterns can be real ReDoS: report those, do not wait for them
FLAGS = { "i" => Regexp::IGNORECASE, "x" => Regexp::EXTENDED, "m" => Regexp::MULTILINE }
out = JSON.parse(File.read(ARGV[0], encoding: "UTF-8")).map do |c|
  anchor = c["anchor_at"]
  begin
    source = anchor ? "\\G(?:#{c["pattern"]})" : c["pattern"]
    r = Regexp.new(source, c["flags"].chars.map { |f| FLAGS.fetch(f) }.reduce(0, :|))
  rescue RegexpError, SyntaxError => e
    next({ "error" => e.message })
  end
  spans = c["inputs"].map do |s|
    m = anchor ? r.match(s, anchor) : r.match(s)
    m ? [m.begin(0), m.end(0)] : nil
  rescue RegexpError, Regexp::TimeoutError => e # Ruby's own failures (e.g. "failed to allocate memory"): reported, not compared
    { "crash" => "#{e.class}: #{e.message}" }
  end
  { "spans" => spans }
end
print JSON.generate(out)
