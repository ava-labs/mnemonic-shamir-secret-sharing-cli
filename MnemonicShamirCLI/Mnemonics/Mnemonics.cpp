// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Mnemonics.h"
#include "Hashing.h"
#include <unordered_map>

using namespace std;

// Word list taken from https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
const static vector<string> word_list = {
    "abandon",  "ability",  "able",     "about",    "above",    "absent",   "absorb",   "abstract", "absurd",
    "abuse",    "access",   "accident", "account",  "accuse",   "achieve",  "acid",     "acoustic", "acquire",
    "across",   "act",      "action",   "actor",    "actress",  "actual",   "adapt",    "add",      "addict",
    "address",  "adjust",   "admit",    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",
    "afraid",   "again",    "age",      "agent",    "agree",    "ahead",    "aim",      "air",      "airport",
    "aisle",    "alarm",    "album",    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",
    "almost",   "alone",    "alpha",    "already",  "also",     "alter",    "always",   "amateur",  "amazing",
    "among",    "amount",   "amused",   "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",   "antenna",  "antique",  "anxiety",
    "any",      "apart",    "apology",  "appear",   "apple",    "approve",  "april",    "arch",     "arctic",
    "area",     "arena",    "argue",    "arm",      "armed",    "armor",    "army",     "around",   "arrange",
    "arrest",   "arrive",   "arrow",    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",
    "assault",  "asset",    "assist",   "assume",   "asthma",   "athlete",  "atom",     "attack",   "attend",
    "attitude", "attract",  "auction",  "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
    "average",  "avocado",  "avoid",    "awake",    "aware",    "away",     "awesome",  "awful",    "awkward",
    "axis",     "baby",     "bachelor", "bacon",    "badge",    "bag",      "balance",  "balcony",  "ball",
    "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",  "barrel",   "base",     "basic",
    "basket",   "battle",   "beach",    "bean",     "beauty",   "because",  "become",   "beef",     "before",
    "begin",    "behave",   "behind",   "believe",  "below",    "belt",     "bench",    "benefit",  "best",
    "betray",   "better",   "between",  "beyond",   "bicycle",  "bid",      "bike",     "bind",     "biology",
    "bird",     "birth",    "bitter",   "black",    "blade",    "blame",    "blanket",  "blast",    "bleak",
    "bless",    "blind",    "blood",    "blossom",  "blouse",   "blue",     "blur",     "blush",    "board",
    "boat",     "body",     "boil",     "bomb",     "bone",     "bonus",    "book",     "boost",    "border",
    "boring",   "borrow",   "boss",     "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",
    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",    "bridge",   "brief",    "bright",
    "bring",    "brisk",    "broccoli", "broken",   "bronze",   "broom",    "brother",  "brown",    "brush",
    "bubble",   "buddy",    "budget",   "buffalo",  "build",    "bulb",     "bulk",     "bullet",   "bundle",
    "bunker",   "burden",   "burger",   "burst",    "bus",      "business", "busy",     "butter",   "buyer",
    "buzz",     "cabbage",  "cabin",    "cable",    "cactus",   "cage",     "cake",     "call",     "calm",
    "camera",   "camp",     "can",      "canal",    "cancel",   "candy",    "cannon",   "canoe",    "canvas",
    "canyon",   "capable",  "capital",  "captain",  "car",      "carbon",   "card",     "cargo",    "carpet",
    "carry",    "cart",     "case",     "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",
    "catch",    "category", "cattle",   "caught",   "cause",    "caution",  "cave",     "ceiling",  "celery",
    "cement",   "census",   "century",  "cereal",   "certain",  "chair",    "chalk",    "champion", "change",
    "chaos",    "chapter",  "charge",   "chase",    "chat",     "cheap",    "check",    "cheese",   "chef",
    "cherry",   "chest",    "chicken",  "chief",    "child",    "chimney",  "choice",   "choose",   "chronic",
    "chuckle",  "chunk",    "churn",    "cigar",    "cinnamon", "circle",   "citizen",  "city",     "civil",
    "claim",    "clap",     "clarify",  "claw",     "clay",     "clean",    "clerk",    "clever",   "click",
    "client",   "cliff",    "climb",    "clinic",   "clip",     "clock",    "clog",     "close",    "cloth",
    "cloud",    "clown",    "club",     "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",
    "code",     "coffee",   "coil",     "coin",     "collect",  "color",    "column",   "combine",  "come",
    "comfort",  "comic",    "common",   "company",  "concert",  "conduct",  "confirm",  "congress", "connect",
    "consider", "control",  "convince", "cook",     "cool",     "copper",   "copy",     "coral",    "core",
    "corn",     "correct",  "cost",     "cotton",   "couch",    "country",  "couple",   "course",   "cousin",
    "cover",    "coyote",   "crack",    "cradle",   "craft",    "cram",     "crane",    "crash",    "crater",
    "crawl",    "crazy",    "cream",    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",
    "critic",   "crop",     "cross",    "crouch",   "crowd",    "crucial",  "cruel",    "cruise",   "crumble",
    "crunch",   "crush",    "cry",      "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",
    "current",  "curtain",  "curve",    "cushion",  "custom",   "cute",     "cycle",    "dad",      "damage",
    "damp",     "dance",    "danger",   "daring",   "dash",     "daughter", "dawn",     "day",      "deal",
    "debate",   "debris",   "decade",   "december", "decide",   "decline",  "decorate", "decrease", "deer",
    "defense",  "define",   "defy",     "degree",   "delay",    "deliver",  "demand",   "demise",   "denial",
    "dentist",  "deny",     "depart",   "depend",   "deposit",  "depth",    "deputy",   "derive",   "describe",
    "desert",   "design",   "desk",     "despair",  "destroy",  "detail",   "detect",   "develop",  "device",
    "devote",   "diagram",  "dial",     "diamond",  "diary",    "dice",     "diesel",   "diet",     "differ",
    "digital",  "dignity",  "dilemma",  "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
    "disease",  "dish",     "dismiss",  "disorder", "display",  "distance", "divert",   "divide",   "divorce",
    "dizzy",    "doctor",   "document", "dog",      "doll",     "dolphin",  "domain",   "donate",   "donkey",
    "donor",    "door",     "dose",     "double",   "dove",     "draft",    "dragon",   "drama",    "drastic",
    "draw",     "dream",    "dress",    "drift",    "drill",    "drink",    "drip",     "drive",    "drop",
    "drum",     "dry",      "duck",     "dumb",     "dune",     "during",   "dust",     "dutch",    "duty",
    "dwarf",    "dynamic",  "eager",    "eagle",    "early",    "earn",     "earth",    "easily",   "east",
    "easy",     "echo",     "ecology",  "economy",  "edge",     "edit",     "educate",  "effort",   "egg",
    "eight",    "either",   "elbow",    "elder",    "electric", "elegant",  "element",  "elephant", "elevator",
    "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",   "emotion",  "employ",   "empower",
    "empty",    "enable",   "enact",    "end",      "endless",  "endorse",  "enemy",    "energy",   "enforce",
    "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",   "enrich",   "enroll",   "ensure",
    "enter",    "entire",   "entry",    "envelope", "episode",  "equal",    "equip",    "era",      "erase",
    "erode",    "erosion",  "error",    "erupt",    "escape",   "essay",    "essence",  "estate",   "eternal",
    "ethics",   "evidence", "evil",     "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange",
    "excite",   "exclude",  "excuse",   "execute",  "exercise", "exhaust",  "exhibit",  "exile",    "exist",
    "exit",     "exotic",   "expand",   "expect",   "expire",   "explain",  "expose",   "express",  "extend",
    "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",  "fade",     "faint",    "faith",
    "fall",     "false",    "fame",     "family",   "famous",   "fan",      "fancy",    "fantasy",  "farm",
    "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",    "favorite", "feature",  "february",
    "federal",  "fee",      "feed",     "feel",     "female",   "fence",    "festival", "fetch",    "fever",
    "few",      "fiber",    "fiction",  "field",    "figure",   "file",     "film",     "filter",   "final",
    "find",     "fine",     "finger",   "finish",   "fire",     "firm",     "first",    "fiscal",   "fish",
    "fit",      "fitness",  "fix",      "flag",     "flame",    "flash",    "flat",     "flavor",   "flee",
    "flight",   "flip",     "float",    "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",
    "foam",     "focus",    "fog",      "foil",     "fold",     "follow",   "food",     "foot",     "force",
    "forest",   "forget",   "fork",     "fortune",  "forum",    "forward",  "fossil",   "foster",   "found",
    "fox",      "fragile",  "frame",    "frequent", "fresh",    "friend",   "fringe",   "frog",     "front",
    "frost",    "frown",    "frozen",   "fruit",    "fuel",     "fun",      "funny",    "furnace",  "fury",
    "future",   "gadget",   "gain",     "galaxy",   "gallery",  "game",     "gap",      "garage",   "garbage",
    "garden",   "garlic",   "garment",  "gas",      "gasp",     "gate",     "gather",   "gauge",    "gaze",
    "general",  "genius",   "genre",    "gentle",   "genuine",  "gesture",  "ghost",    "giant",    "gift",
    "giggle",   "ginger",   "giraffe",  "girl",     "give",     "glad",     "glance",   "glare",    "glass",
    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",    "glow",     "glue",     "goat",
    "goddess",  "gold",     "good",     "goose",    "gorilla",  "gospel",   "gossip",   "govern",   "gown",
    "grab",     "grace",    "grain",    "grant",    "grape",    "grass",    "gravity",  "great",    "green",
    "grid",     "grief",    "grit",     "grocery",  "group",    "grow",     "grunt",    "guard",    "guess",
    "guide",    "guilt",    "guitar",   "gun",      "gym",      "habit",    "hair",     "half",     "hammer",
    "hamster",  "hand",     "happy",    "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",
    "hawk",     "hazard",   "head",     "health",   "heart",    "heavy",    "hedgehog", "height",   "hello",
    "helmet",   "help",     "hen",      "hero",     "hidden",   "high",     "hill",     "hint",     "hip",
    "hire",     "history",  "hobby",    "hockey",   "hold",     "hole",     "holiday",  "hollow",   "home",
    "honey",    "hood",     "hope",     "horn",     "horror",   "horse",    "hospital", "host",     "hotel",
    "hour",     "hover",    "hub",      "huge",     "human",    "humble",   "humor",    "hundred",  "hungry",
    "hunt",     "hurdle",   "hurry",    "hurt",     "husband",  "hybrid",   "ice",      "icon",     "idea",
    "identify", "idle",     "ignore",   "ill",      "illegal",  "illness",  "image",    "imitate",  "immense",
    "immune",   "impact",   "impose",   "improve",  "impulse",  "inch",     "include",  "income",   "increase",
    "index",    "indicate", "indoor",   "industry", "infant",   "inflict",  "inform",   "inhale",   "inherit",
    "initial",  "inject",   "injury",   "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",
    "insect",   "inside",   "inspire",  "install",  "intact",   "interest", "into",     "invest",   "invite",
    "involve",  "iron",     "island",   "isolate",  "issue",    "item",     "ivory",    "jacket",   "jaguar",
    "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",    "job",      "join",     "joke",
    "journey",  "joy",      "judge",    "juice",    "jump",     "jungle",   "junior",   "junk",     "just",
    "kangaroo", "keen",     "keep",     "ketchup",  "key",      "kick",     "kid",      "kidney",   "kind",
    "kingdom",  "kiss",     "kit",      "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",
    "knock",    "know",     "lab",      "label",    "labor",    "ladder",   "lady",     "lake",     "lamp",
    "language", "laptop",   "large",    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
    "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",     "learn",    "leave",    "lecture",
    "left",     "leg",      "legal",    "legend",   "leisure",  "lemon",    "lend",     "length",   "lens",
    "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",  "library",  "license",  "life",
    "lift",     "light",    "like",     "limb",     "limit",    "link",     "lion",     "liquid",   "list",
    "little",   "live",     "lizard",   "load",     "loan",     "lobster",  "local",    "lock",     "logic",
    "lonely",   "long",     "loop",     "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",
    "luggage",  "lumber",   "lunar",    "lunch",    "luxury",   "lyrics",   "machine",  "mad",      "magic",
    "magnet",   "maid",     "mail",     "main",     "major",    "make",     "mammal",   "man",      "manage",
    "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",   "march",    "margin",   "marine",
    "market",   "marriage", "mask",     "mass",     "master",   "match",    "material", "math",     "matrix",
    "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",  "meat",     "mechanic", "medal",
    "media",    "melody",   "melt",     "member",   "memory",   "mention",  "menu",     "mercy",    "merge",
    "merit",    "merry",    "mesh",     "message",  "metal",    "method",   "middle",   "midnight", "milk",
    "million",  "mimic",    "mind",     "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",
    "miss",     "mistake",  "mix",      "mixed",    "mixture",  "mobile",   "model",    "modify",   "mom",
    "moment",   "monitor",  "monkey",   "monster",  "month",    "moon",     "moral",    "more",     "morning",
    "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",    "move",     "movie",    "much",
    "muffin",   "mule",     "multiply", "muscle",   "museum",   "mushroom", "music",    "must",     "mutual",
    "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",   "narrow",   "nasty",    "nation",
    "nature",   "near",     "neck",     "need",     "negative", "neglect",  "neither",  "nephew",   "nerve",
    "nest",     "net",      "network",  "neutral",  "never",    "news",     "next",     "nice",     "night",
    "noble",    "noise",    "nominee",  "noodle",   "normal",   "north",    "nose",     "notable",  "note",
    "nothing",  "notice",   "novel",    "now",      "nuclear",  "number",   "nurse",    "nut",      "oak",
    "obey",     "object",   "oblige",   "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",
    "october",  "odor",     "off",      "offer",    "office",   "often",    "oil",      "okay",     "old",
    "olive",    "olympic",  "omit",     "once",     "one",      "onion",    "online",   "only",     "open",
    "opera",    "opinion",  "oppose",   "option",   "orange",   "orbit",    "orchard",  "order",    "ordinary",
    "organ",    "orient",   "original", "orphan",   "ostrich",  "other",    "outdoor",  "outer",    "output",
    "outside",  "oval",     "oven",     "over",     "own",      "owner",    "oxygen",   "oyster",   "ozone",
    "pact",     "paddle",   "page",     "pair",     "palace",   "palm",     "panda",    "panel",    "panic",
    "panther",  "paper",    "parade",   "parent",   "park",     "parrot",   "party",    "pass",     "patch",
    "path",     "patient",  "patrol",   "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",
    "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",   "people",   "pepper",   "perfect",
    "permit",   "person",   "pet",      "phone",    "photo",    "phrase",   "physical", "piano",    "picnic",
    "picture",  "piece",    "pig",      "pigeon",   "pill",     "pilot",    "pink",     "pioneer",  "pipe",
    "pistol",   "pitch",    "pizza",    "place",    "planet",   "plastic",  "plate",    "play",     "please",
    "pledge",   "pluck",    "plug",     "plunge",   "poem",     "poet",     "point",    "polar",    "pole",
    "police",   "pond",     "pony",     "pool",     "popular",  "portion",  "position", "possible", "post",
    "potato",   "pottery",  "poverty",  "powder",   "power",    "practice", "praise",   "predict",  "prefer",
    "prepare",  "present",  "pretty",   "prevent",  "price",    "pride",    "primary",  "print",    "priority",
    "prison",   "private",  "prize",    "problem",  "process",  "produce",  "profit",   "program",  "project",
    "promote",  "proof",    "property", "prosper",  "protect",  "proud",    "provide",  "public",   "pudding",
    "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",    "puppy",    "purchase", "purity",
    "purpose",  "purse",    "push",     "put",      "puzzle",   "pyramid",  "quality",  "quantum",  "quarter",
    "question", "quick",    "quit",     "quiz",     "quote",    "rabbit",   "raccoon",  "race",     "rack",
    "radar",    "radio",    "rail",     "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",
    "range",    "rapid",    "rare",     "rate",     "rather",   "raven",    "raw",      "razor",    "ready",
    "real",     "reason",   "rebel",    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",
    "reduce",   "reflect",  "reform",   "refuse",   "region",   "regret",   "regular",  "reject",   "relax",
    "release",  "relief",   "rely",     "remain",   "remember", "remind",   "remove",   "render",   "renew",
    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",   "require",  "rescue",   "resemble",
    "resist",   "resource", "response", "result",   "retire",   "retreat",  "return",   "reunion",  "reveal",
    "review",   "reward",   "rhythm",   "rib",      "ribbon",   "rice",     "rich",     "ride",     "ridge",
    "rifle",    "right",    "rigid",    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",
    "river",    "road",     "roast",    "robot",    "robust",   "rocket",   "romance",  "roof",     "rookie",
    "room",     "rose",     "rotate",   "rough",    "round",    "route",    "royal",    "rubber",   "rude",
    "rug",      "rule",     "run",      "runway",   "rural",    "sad",      "saddle",   "sadness",  "safe",
    "sail",     "salad",    "salmon",   "salon",    "salt",     "salute",   "same",     "sample",   "sand",
    "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",      "scale",    "scan",     "scare",
    "scatter",  "scene",    "scheme",   "school",   "science",  "scissors", "scorpion", "scout",    "scrap",
    "screen",   "script",   "scrub",    "sea",      "search",   "season",   "seat",     "second",   "secret",
    "section",  "security", "seed",     "seek",     "segment",  "select",   "sell",     "seminar",  "senior",
    "sense",    "sentence", "series",   "service",  "session",  "settle",   "setup",    "seven",    "shadow",
    "shaft",    "shallow",  "share",    "shed",     "shell",    "sheriff",  "shield",   "shift",    "shine",
    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",     "short",    "shoulder", "shove",
    "shrimp",   "shrug",    "shuffle",  "shy",      "sibling",  "sick",     "side",     "siege",    "sight",
    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",  "simple",   "since",    "sing",
    "siren",    "sister",   "situate",  "six",      "size",     "skate",    "sketch",   "ski",      "skill",
    "skin",     "skirt",    "skull",    "slab",     "slam",     "sleep",    "slender",  "slice",    "slide",
    "slight",   "slim",     "slogan",   "slot",     "slow",     "slush",    "small",    "smart",    "smile",
    "smoke",    "smooth",   "snack",    "snake",    "snap",     "sniff",    "snow",     "soap",     "soccer",
    "social",   "sock",     "soda",     "soft",     "solar",    "soldier",  "solid",    "solution", "solve",
    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",     "sound",    "soup",     "source",
    "south",    "space",    "spare",    "spatial",  "spawn",    "speak",    "special",  "speed",    "spell",
    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",     "spirit",   "split",    "spoil",
    "sponsor",  "spoon",    "sport",    "spot",     "spray",    "spread",   "spring",   "spy",      "square",
    "squeeze",  "squirrel", "stable",   "stadium",  "staff",    "stage",    "stairs",   "stamp",    "stand",
    "start",    "state",    "stay",     "steak",    "steel",    "stem",     "step",     "stereo",   "stick",
    "still",    "sting",    "stock",    "stomach",  "stone",    "stool",    "story",    "stove",    "strategy",
    "street",   "strike",   "strong",   "struggle", "student",  "stuff",    "stumble",  "style",    "subject",
    "submit",   "subway",   "success",  "such",     "sudden",   "suffer",   "sugar",    "suggest",  "suit",
    "summer",   "sun",      "sunny",    "sunset",   "super",    "supply",   "supreme",  "sure",     "surface",
    "surge",    "surprise", "surround", "survey",   "suspect",  "sustain",  "swallow",  "swamp",    "swap",
    "swarm",    "swear",    "sweet",    "swift",    "swim",     "swing",    "switch",   "sword",    "symbol",
    "symptom",  "syrup",    "system",   "table",    "tackle",   "tag",      "tail",     "talent",   "talk",
    "tank",     "tape",     "target",   "task",     "taste",    "tattoo",   "taxi",     "teach",    "team",
    "tell",     "ten",      "tenant",   "tennis",   "tent",     "term",     "test",     "text",     "thank",
    "that",     "theme",    "then",     "theory",   "there",    "they",     "thing",    "this",     "thought",
    "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",   "tide",     "tiger",    "tilt",
    "timber",   "time",     "tiny",     "tip",      "tired",    "tissue",   "title",    "toast",    "tobacco",
    "today",    "toddler",  "toe",      "together", "toilet",   "token",    "tomato",   "tomorrow", "tone",
    "tongue",   "tonight",  "tool",     "tooth",    "top",      "topic",    "topple",   "torch",    "tornado",
    "tortoise", "toss",     "total",    "tourist",  "toward",   "tower",    "town",     "toy",      "track",
    "trade",    "traffic",  "tragic",   "train",    "transfer", "trap",     "trash",    "travel",   "tray",
    "treat",    "tree",     "trend",    "trial",    "tribe",    "trick",    "trigger",  "trim",     "trip",
    "trophy",   "trouble",  "truck",    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",
    "tube",     "tuition",  "tumble",   "tuna",     "tunnel",   "turkey",   "turn",     "turtle",   "twelve",
    "twenty",   "twice",    "twin",     "twist",    "two",      "type",     "typical",  "ugly",     "umbrella",
    "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",     "unfair",   "unfold",   "unhappy",
    "uniform",  "unique",   "unit",     "universe", "unknown",  "unlock",   "until",    "unusual",  "unveil",
    "update",   "upgrade",  "uphold",   "upon",     "upper",    "upset",    "urban",    "urge",     "usage",
    "use",      "used",     "useful",   "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",
    "valid",    "valley",   "valve",    "van",      "vanish",   "vapor",    "various",  "vast",     "vault",
    "vehicle",  "velvet",   "vendor",   "venture",  "venue",    "verb",     "verify",   "version",  "very",
    "vessel",   "veteran",  "viable",   "vibrant",  "vicious",  "victory",  "video",    "view",     "village",
    "vintage",  "violin",   "virtual",  "virus",    "visa",     "visit",    "visual",   "vital",    "vivid",
    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",     "voyage",   "wage",     "wagon",
    "wait",     "walk",     "wall",     "walnut",   "want",     "warfare",  "warm",     "warrior",  "wash",
    "wasp",     "waste",    "water",    "wave",     "way",      "wealth",   "weapon",   "wear",     "weasel",
    "weather",  "web",      "wedding",  "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",
    "what",     "wheat",    "wheel",    "when",     "where",    "whip",     "whisper",  "wide",     "width",
    "wife",     "wild",     "will",     "win",      "window",   "wine",     "wing",     "wink",     "winner",
    "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",  "wolf",     "woman",    "wonder",
    "wood",     "wool",     "word",     "work",     "world",    "worry",    "worth",    "wrap",     "wreck",
    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",     "yellow",   "you",      "young",
    "youth",    "zebra",    "zero",     "zone",     "zoo"
};

// Store the word list as a map to optimize index look ups.
static std::unordered_map<string, uint16_t> word_map;
// Store the word list trimming the first 4 characters of each word as a map
static std::map<string, string> word_map_abbr;

void initialize_mnemonic_word_map() {
    word_map.clear();
    for (uint16_t i = 0; i < uint16_t(word_list.size()); i++) {
        word_map[word_list[i]] = i;
    }
}

void initialize_mnemonic_word_map_abbreviated() {
    word_map_abbr.clear();
    for (uint16_t i = 0; i < uint16_t(word_list.size()); i++) {
        std::string word = word_list[i];
        std::string word_abbr = word.substr(0, 4);
        auto it = word_map_abbr.find(word_abbr);
        if (it == word_map_abbr.end()) {
            word_map_abbr[word_abbr] = word;
        } else {
            std::cout << "Error initializing the abbreviated word map. The abbreviated word \"" << word_abbr
                      << "\" was already in memory." << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}

bool validate_word(const bool is_abbreviated, const std::string& word_input, Mnemonics<std::string>* mnemonics_list) {
    if (is_abbreviated) {
        auto it = word_map_abbr.find(word_input);
        if (it == word_map_abbr.end()) {
            if (word_input.size() > 4) {
                std::cout << "More than 4 characters input. Please enter only the first 4 characters of the word."
                          << std::endl;
            } else if (word_input != "") {
                std::cout << "Invalid 4 characters of the mnemonic. \"" << word_input << "\" is not in the word list."
                          << std::endl;
            }
            return false;
        }
        mnemonics_list->push_back(it->second);
    } else {
        auto it = word_map.find(word_input);
        if (it == word_map.end()) {
            if (word_input != "") {
                std::cout << "Invalid word. \"" << word_input << "\" is not in the word list." << std::endl;
            }
            return false;
        }
        mnemonics_list->push_back(it->first);
    }
    return true;
}

void input_mnemonics_list(const int share_num,
                          const int quorum,
                          Mnemonics<std::string>* mnemonics_list,
                          const bool is_abbreviated,
                          const bool word_by_word) {
    // If not initialized, initialize the word_map and the word_map_abbr
    if (word_map_abbr.size() == 0) {
        initialize_mnemonic_word_map_abbreviated();
    }
    if (word_map.size() == 0) {
        initialize_mnemonic_word_map();
    }
    bool validated_correctly;
    do {
        validated_correctly = false;
        if (word_by_word) {
            if (is_abbreviated) {
                print_message(
                    "Please enter the first 4 characters of each word of the 24 word mnemonic phrase. Press return key after each word.");
            } else {
                print_message("Please enter each word of the 24 word mnemonic phrase. Press return key after each word.");
            }
        } else {
            // by phrase
            if (is_abbreviated) {
                print_message(
                    "Please enter a 24 abbreviated word mnemonic phrase, words separated by single white space. Press return key after entering the phrase.");
            } else {
                print_message(
                    "Please enter a 24 word mnemonic phrase, words separated by single white space. Press return key after entering the phrase.");
            }
        }
        if (quorum != 0) {
            print_message("(share %d of %d)", share_num, quorum);
        }
        // Removes all elements from the vector
        mnemonics_list->clear();
        if (word_by_word) {
            for (int i = 0; i < MNEMONIC_WORD_COUNT;) {
                std::cout << i + 1 << ": ";
                std::string word_input = "";
                std::getline(std::cin, word_input);
                std::string normalized_word = tolowercase(trim(word_input));
                if (!validate_word(is_abbreviated, normalized_word, mnemonics_list)) {
                    OPENSSL_cleanse(&word_input[0], word_input.size());
                    OPENSSL_cleanse(&normalized_word[0], normalized_word.size());
                    continue;
                }
                OPENSSL_cleanse(&word_input[0], word_input.size());
                OPENSSL_cleanse(&normalized_word[0], normalized_word.size());
                i++;
            }
        } else {
            // by phrase
            std::string phrase_input;
            std::getline(std::cin, phrase_input);

            std::string normalized_phrase = tolowercase(trim(phrase_input));
            Mnemonics<std::string> words;

            split_string(normalized_phrase, std::string(MNEMONIC_WORD_DELIMITER), &words);

            OPENSSL_cleanse(&phrase_input[0], phrase_input.size());
            OPENSSL_cleanse(&normalized_phrase[0], normalized_phrase.size());

            if (words.size() != MNEMONIC_WORD_COUNT) {
                print_message("Wrong word count. Expected %lu, got %lu", MNEMONIC_WORD_COUNT, words.size());
                validated_correctly = false;
                continue;
            }
            bool validated_word = true;
            for (auto& w : words) {
                if (!validate_word(is_abbreviated, w, mnemonics_list)) {
                    validated_word = false;
                }
            }
            if (!validated_word) {
                validated_correctly = false;
                continue;
            }
        }
        validated_correctly = validate_mnemonic(*mnemonics_list);
    } while (!validated_correctly);
}

// Calculates the decimal value of the 11 bits starting at offset bits of pa||pb||pc. For example, take pa=10100101,
// pb=00111101, pc=10011110, and offset to be 6. The result is constructed by skipping the first 6 bits of pa, and then
// taking the value of the next 11 bits. In this case, the binary result is 01001111011. We pad 5 zeros at the start to
// bring us to 16 bits, and the result value is 635.
inline uint16_t calculate_word_index(const unsigned char pa,
                                     const unsigned char pb,
                                     const unsigned char pc,
                                     const uint32_t offset) {
    ASSERT(offset < 8, "Invalid offset given to calculate_word_index.")
    uint16_t a = (uint16_t) 0x00FF & (uint16_t) pa;
    uint16_t b = (uint16_t) 0x00FF & (uint16_t) pb;
    uint16_t c = (uint16_t) 0x00FF & (uint16_t) pc;

    uint16_t x = a << (8 + offset);
    uint16_t y = b << offset;

    uint16_t res = 0;
    if (offset < 6) {
        res = (x | y) >> 5;
    } else {
        uint16_t z = c >> (8 - offset);
        res = (x | y | z) >> 5;
    }

    return res;
}

// Validates that passed mnemonic is 24 words and each word is in the word list
bool validate_mnemonic(const Mnemonics<std::string>& mnemonic) {
    // Check the mnemonic size is correct.
    if (mnemonic.size() != MNEMONIC_WORD_COUNT) {
        print_message("Wrong word count. Expected %lu, got %lu", MNEMONIC_WORD_COUNT, mnemonic.size());
        return false;
    }

    // Create a word map for faster lookup
    if (word_map.empty()) {
        initialize_mnemonic_word_map();
    }

    // Check that every word is in the word list
    Mnemonics<std::string> mnemonic_copy(mnemonic);
    for (auto& word : mnemonic_copy) {
        auto index_it = word_map.find(word);
        if (index_it == word_map.end()) {
            print_message("Word not in the word list: %s", word.c_str());
            return false;
        }
    }

    // Convert mnemonic into 256 bit secret
    BIGNUM* bn = nullptr;
    if (derive_key_from_mnemonic(mnemonic_copy, &bn) != 0) {
        if (bn != nullptr) {
            BN_clear_free(bn);
        }
        return false;
    }

    if (bn != nullptr) {
        BN_clear_free(bn);
    }
    return true;
}

// Generates a 24 word mnemonic from passed 256 bit entropy and stores it in result
void generate_mnemonic(const BIGNUM* entropy, Mnemonics<std::string>* result) {
    // The entropy must be 32 bytes (256 bits).
    // If the BIGNUM provided has a leading zero, it may not take up 32 bytes. In this case,
    // we prepend the proper number of zeros to make the entropy buffer 32 bytes.
    int entropy_decimal_size = BN_num_bytes(entropy);

    ASSERT(entropy_decimal_size <= MNEMONIC_ENTROPY_SIZE, "Invalid entropy size given to generate_mnemonic.")

    // Compute the SHA256 hash of the entropy to generate the checksum.
    unsigned char entropy_buff[MNEMONIC_ENTROPY_SIZE] = { 0 };
    unsigned char checksum_buff[SHA256_DIGEST_LENGTH] = { 0 };
    BN_bn2bin(entropy, entropy_buff + (MNEMONIC_ENTROPY_SIZE - entropy_decimal_size));
    sha256(entropy_buff, MNEMONIC_ENTROPY_SIZE, checksum_buff);

    // Serialize a buffer with the entropy + checksum to compute the mnemonic from.
    unsigned char mnemonic_buff[MNEMONIC_BYTE_SIZE] = { 0 };
    memcpy(mnemonic_buff, entropy_buff, MNEMONIC_ENTROPY_SIZE);
    mnemonic_buff[MNEMONIC_BYTE_SIZE - 1] = checksum_buff[0];

    // Calculate the index into the word list to use for each word and construct the result.
    for (uint32_t i = 0; i < MNEMONIC_WORD_COUNT; i++) {
        uint32_t bit_start_index = i * 11;
        uint32_t byte_start_index = bit_start_index / 8;
        uint32_t offset = bit_start_index % 8;

        // Make sure we don't go into an index out of bounds on the last iteration.
        // This is okay because the final iteration has an offset of 5, and only uses 2 bytes.
        uint16_t word_index;

        if (i == MNEMONIC_WORD_COUNT - 1) {
            ASSERT(byte_start_index + 1 < MNEMONIC_BYTE_SIZE, "Invalid byte_start_index calculated in generate_mnemonic.")
            word_index =
                calculate_word_index(mnemonic_buff[byte_start_index], mnemonic_buff[byte_start_index + 1], 0x00, offset);
        } else {
            ASSERT(byte_start_index + 2 < MNEMONIC_BYTE_SIZE, "Invalid byte_start_index calculated in generate_mnemonic.")
            word_index = calculate_word_index(mnemonic_buff[byte_start_index],
                                              mnemonic_buff[byte_start_index + 1],
                                              mnemonic_buff[byte_start_index + 2],
                                              offset);
        }

        ASSERT(word_index < word_list.size(), "Invalid word index calculated in generate_mnemonic.")
        result->push_back(word_list[word_index]);
    }

    // Cleanup

    OPENSSL_cleanse(entropy_buff, MNEMONIC_ENTROPY_SIZE);
    OPENSSL_cleanse(checksum_buff, SHA256_DIGEST_LENGTH);
    OPENSSL_cleanse(mnemonic_buff, MNEMONIC_BYTE_SIZE);

    return;
}

// Recover 256 bit entropy from provided 24 word mnemonic
int derive_key_from_mnemonic(const Mnemonics<std::string>& mnemonic, BIGNUM** result) {

    // Get the index of each word in the mnemonic.
    std::vector<uint16_t> word_indices;
    Mnemonics<std::string> mnemonic_copy(mnemonic);
    for (const auto& word : mnemonic_copy) {
        auto index_it = word_map.find(word);
        if (index_it == word_map.end()) {
            print_message("Word not in the word list: %s", word.c_str());
            return -1;
        }
        word_indices.push_back(index_it->second);
    }

    // Convert the decimal indices back into the mnemonic buffer by converting the indices into 11 bit values.
    unsigned char mnemonic_buff[MNEMONIC_BYTE_SIZE] = { 0 };
    for (uint32_t i = 0; i < word_indices.size(); i++) {
        // For simplicity, we left shift the value by 5 bits so that the 11 significant bits are leading.
        uint16_t word_index = word_indices[i] << 5;

        uint32_t bit_start_index = i * 11;
        uint32_t byte_start_index = bit_start_index / 8;
        uint32_t offset = bit_start_index % 8;

        uint8_t zero_index;
        uint8_t one_index;

        if (is_big_endian()) {
            zero_index = 0;
            one_index = 1;
        } else {
            zero_index = 1;
            one_index = 0;
        }

        // Fill the proper bits of the result buffer with the 11 significant bits of this word_index.
        uint8_t bits_to_keep = (uint8_t) 0xFF << (8 - offset);
        ASSERT(byte_start_index + 1 < MNEMONIC_BYTE_SIZE,
               "Invalid byte_start_index calculated in derive_key_from_mnemonic.")
        mnemonic_buff[byte_start_index] = (mnemonic_buff[byte_start_index] & bits_to_keep) |
                                          (((unsigned char*) &word_index)[zero_index] >> offset);
        mnemonic_buff[byte_start_index + 1] = (((unsigned char*) &word_index)[zero_index] << (8 - offset)) |
                                              (((unsigned char*) &word_index)[one_index] >> offset);
        if (offset >= 6) {
            ASSERT(byte_start_index + 2 < MNEMONIC_BYTE_SIZE,
                   "Invalid byte_start_index calculated in derive_key_from_mnemonic.")
            mnemonic_buff[byte_start_index + 2] = (((unsigned char*) &word_index)[one_index] << (8 - offset));
        }
    }

    // Validate the checksum of the mnemonic.
    unsigned char checksum_buff[SHA256_DIGEST_LENGTH] = { 0 };
    sha256(mnemonic_buff, MNEMONIC_ENTROPY_SIZE, checksum_buff);

    if (checksum_buff[0] != mnemonic_buff[MNEMONIC_BYTE_SIZE - 1]) {
        print_message("Bad checksum");
        return -1;
    }

    // Convert the buffer into the resulting BIGNUM.
    *result = BN_bin2bn(mnemonic_buff, MNEMONIC_ENTROPY_SIZE, nullptr);

    // Cleanup
    OPENSSL_cleanse(checksum_buff, SHA256_DIGEST_LENGTH);
    OPENSSL_cleanse(mnemonic_buff, MNEMONIC_BYTE_SIZE);

    return 0;
}

std::string mnemonic_to_string(const std::vector<std::string>& mnemonic) {
    std::string phrase = "";
    for (const auto& word : mnemonic) {
        phrase += word + " ";
    }
    return phrase;
}
