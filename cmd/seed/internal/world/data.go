package world

import (
	"fmt"
	"strings"
)

// Locale is where a person comes from: the names common there, the cities
// they work in, and how their phone numbers look.
type Locale struct {
	Country   string
	First     []string
	Last      []string
	Cities    []City
	phone     func(w *World) string
	MobileOS  []string // "android" and "ios", weighted by repetition
	DesktopOS []string // "mac", "windows" and "linux", weighted by repetition
}

// City is an office city and the documentation-range block its addresses
// come from (RFC 5737, never routed).
type City struct {
	Name   string
	Office string // the office's egress address
	Block  string // home and mobile addresses, as a /24 prefix plus a range
	Lo, Hi int
}

var (
	// India: names from across the country.
	India = Locale{
		Country: "IN",
		First: []string{
			"Aarav", "Vivaan", "Aditya", "Arjun", "Sai", "Reyansh", "Krishna", "Ishaan", "Kabir", "Dhruv",
			"Karthik", "Pranav", "Siddharth", "Rahul", "Nikhil", "Varun", "Harsh", "Manish", "Suresh", "Venkatesh",
			"Srinivas", "Naveen", "Abhishek", "Akash", "Gaurav", "Rajat", "Imran", "Faisal", "Joseph", "Anil",
			"Deepak", "Prakash", "Ganesh", "Vijay", "Arnav", "Yash", "Tejas", "Ashwin", "Mohit", "Sandeep",
			"Ananya", "Diya", "Saanvi", "Aadhya", "Ishita", "Pooja", "Kavya", "Meera", "Nisha", "Divya",
			"Shreya", "Anjali", "Neha", "Riya", "Lakshmi", "Deepika", "Swati", "Aishwarya", "Keerthi", "Harini",
			"Pallavi", "Shalini", "Sana", "Ayesha", "Fatima", "Jyoti", "Rekha", "Bhavana", "Sowmya", "Madhuri",
			"Tanvi", "Nandini", "Revathi", "Gayatri", "Snehal", "Radhika", "Aparna", "Mansi",
		},
		Last: []string{
			"Sharma", "Verma", "Gupta", "Agarwal", "Mehta", "Shah", "Patel", "Desai", "Joshi", "Kulkarni",
			"Deshpande", "Patil", "Iyer", "Iyengar", "Krishnan", "Subramanian", "Raghavan", "Nair", "Menon", "Pillai",
			"Reddy", "Rao", "Naidu", "Chowdary", "Banerjee", "Chatterjee", "Mukherjee", "Das", "Ghosh", "Bose",
			"Singh", "Kapoor", "Malhotra", "Khanna", "Chopra", "Bhatia", "Sethi", "Khan", "Siddiqui", "Qureshi",
			"Fernandes", "Kamath", "Hegde", "Shetty", "Bhat", "Naik", "Mishra", "Tiwari", "Pandey", "Saxena",
			"Srivastava", "Jain", "Bansal", "Goyal", "Mittal", "Chauhan", "Thakur", "Gill", "Dutta", "Varghese",
		},
		Cities: []City{
			{"Bengaluru", "203.0.113.10", "203.0.113.", 11, 59},
			{"Mumbai", "203.0.113.60", "203.0.113.", 61, 109},
			{"Pune", "203.0.113.110", "203.0.113.", 111, 139},
			{"Hyderabad", "203.0.113.140", "203.0.113.", 141, 169},
			{"Chennai", "203.0.113.170", "203.0.113.", 171, 199},
			{"Gurugram", "203.0.113.200", "203.0.113.", 201, 229},
		},
		phone:     func(w *World) string { return fmt.Sprintf("+9198765%05d", w.Rand.IntN(100000)) },
		MobileOS:  []string{"android", "android", "android", "ios"},
		DesktopOS: []string{"windows", "windows", "mac", "mac", "linux"},
	}
	// UnitedStates: a mix of the country's common names.
	UnitedStates = Locale{
		Country: "US",
		First: []string{
			"James", "Michael", "Robert", "David", "William", "Daniel", "Matthew", "Joseph", "Christopher", "Andrew",
			"Joshua", "Ryan", "Brandon", "Tyler", "Kevin", "Jason", "Marcus", "Andre", "Carlos", "Luis",
			"Diego", "Wei", "Kenji", "Ethan", "Noah", "Liam", "Owen", "Darnell",
			"Mary", "Jennifer", "Jessica", "Sarah", "Emily", "Ashley", "Amanda", "Megan", "Rachel", "Lauren",
			"Hannah", "Olivia", "Emma", "Sophia", "Madison", "Grace", "Chloe", "Maria", "Sofia", "Gabriela",
			"Jasmine", "Aaliyah", "Keisha", "Mei", "Hana", "Nicole", "Rebecca", "Katherine",
		},
		Last: []string{
			"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
			"Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
			"Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
			"Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
			"Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
			"Kim", "Chen", "Murphy", "Sullivan", "Coleman", "Brooks", "Washington", "Park",
		},
		Cities: []City{
			{"Boston", "198.51.100.10", "198.51.100.", 11, 59},
			{"Chicago", "198.51.100.60", "198.51.100.", 61, 109},
			{"New York", "198.51.100.110", "198.51.100.", 111, 149},
			{"Austin", "198.51.100.150", "198.51.100.", 151, 189},
			{"Seattle", "198.51.100.190", "198.51.100.", 191, 229},
		},
		phone: func(w *World) string {
			return fmt.Sprintf("+1%s55501%02d", Pick(w, []string{"617", "312", "212", "512", "206"}), w.Rand.IntN(100))
		},
		MobileOS:  []string{"ios", "ios", "ios", "android", "android"},
		DesktopOS: []string{"windows", "windows", "windows", "mac", "mac"},
	}
	// Germany: German names, with the umlauts.
	Germany = Locale{
		Country: "DE",
		First: []string{
			"Lukas", "Leon", "Finn", "Jonas", "Paul", "Felix", "Maximilian", "Elias", "Ben", "Julian",
			"Moritz", "Tobias", "Jan", "Niklas", "Florian", "Sebastian", "Stefan", "Matthias", "Markus", "Emre",
			"Anna", "Lena", "Laura", "Lea", "Hannah", "Mia", "Sophie", "Emma", "Marie", "Julia",
			"Katharina", "Sarah", "Lisa", "Johanna", "Clara", "Charlotte", "Franziska", "Svenja", "Elif", "Jörg",
		},
		Last: []string{
			"Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz", "Hoffmann",
			"Schäfer", "Koch", "Bauer", "Richter", "Klein", "Wolf", "Schröder", "Neumann", "Schwarz", "Zimmermann",
			"Braun", "Krüger", "Hofmann", "Hartmann", "Lange", "Schmitt", "Werner", "Krause", "Meier", "Lehmann",
			"Yılmaz", "Kaya", "Nowak", "Kowalski",
		},
		Cities: []City{
			{"Berlin", "192.0.2.10", "192.0.2.", 11, 59},
			{"Munich", "192.0.2.60", "192.0.2.", 61, 89},
			{"Hamburg", "192.0.2.90", "192.0.2.", 91, 109},
		},
		phone:     func(w *World) string { return fmt.Sprintf("+493023125%03d", w.Rand.IntN(1000)) },
		MobileOS:  []string{"android", "ios", "ios"},
		DesktopOS: []string{"mac", "mac", "linux", "windows"},
	}
	// Britain: British names.
	Britain = Locale{
		Country: "GB",
		First: []string{
			"Oliver", "George", "Harry", "Jack", "Charlie", "Thomas", "James", "William", "Alfie", "Henry",
			"Oscar", "Arthur", "Rory", "Callum", "Ewan", "Amelia", "Olivia", "Isla", "Ava", "Emily",
			"Sophie", "Grace", "Poppy", "Ella", "Freya", "Isabella", "Lily", "Evie", "Imogen", "Niamh",
		},
		Last: []string{
			"Smith", "Jones", "Taylor", "Brown", "Williams", "Wilson", "Johnson", "Davies", "Robinson", "Wright",
			"Thompson", "Evans", "Walker", "White", "Roberts", "Green", "Hall", "Wood", "Clarke", "Hughes",
			"Edwards", "Patel", "Khan", "Ali", "Murray", "Campbell", "Stewart", "Kennedy", "Morgan", "Bennett",
		},
		Cities: []City{
			{"London", "192.0.2.110", "192.0.2.", 111, 149},
			{"Manchester", "192.0.2.150", "192.0.2.", 151, 169},
		},
		phone:     func(w *World) string { return fmt.Sprintf("+447700900%03d", w.Rand.IntN(1000)) },
		MobileOS:  []string{"ios", "ios", "android"},
		DesktopOS: []string{"mac", "mac", "windows"},
	}
	// Norway: Norwegian names.
	Norway = Locale{
		Country: "NO",
		First: []string{
			"Jakob", "Emil", "Noah", "Oliver", "Filip", "Lukas", "Henrik", "Magnus", "Sander", "Erik",
			"Lars", "Ole", "Nora", "Emma", "Ella", "Maja", "Ingrid", "Sofie", "Leah", "Sara",
			"Thea", "Ida", "Silje", "Kari", "Astrid",
		},
		Last: []string{
			"Hansen", "Johansen", "Olsen", "Larsen", "Andersen", "Pedersen", "Nilsen", "Kristiansen", "Jensen", "Karlsen",
			"Johnsen", "Pettersen", "Eriksen", "Berg", "Haugen", "Hagen", "Dahl", "Lunde", "Solberg", "Bakke",
			"Strand", "Moen", "Halvorsen", "Bakken", "Ødegård",
		},
		Cities: []City{
			{"Oslo", "192.0.2.170", "192.0.2.", 171, 199},
		},
		phone:     func(w *World) string { return "" },
		MobileOS:  []string{"ios", "android"},
		DesktopOS: []string{"mac", "windows", "linux"},
	}
	// Europe: the international mix of a Berlin start-up.
	Europe = Locale{
		Country: "DE",
		First: []string{
			"Pierre", "Camille", "Lucía", "Javier", "Matteo", "Giulia", "Sven", "Anouk", "Daan", "Piotr",
			"Zofia", "Mateus", "Ana", "Yuki", "Hiroshi", "Omar", "Layla", "Tomás", "Inès", "Nikolai",
		},
		Last: []string{
			"Dubois", "Moreau", "García", "Fernández", "Rossi", "Bianchi", "de Vries", "Jansen", "Kowalczyk", "Wiśniewska",
			"Silva", "Costa", "Tanaka", "Sato", "Haddad", "Mansour", "Novak", "Horvat", "Lindqvist", "Petrov",
		},
		Cities: []City{
			{"Berlin", "192.0.2.10", "192.0.2.", 11, 59},
		},
		phone:     func(w *World) string { return fmt.Sprintf("+493023125%03d", w.Rand.IntN(1000)) },
		MobileOS:  []string{"ios", "android"},
		DesktopOS: []string{"mac", "mac", "linux"},
	}
)

// Phone returns a phone number from the locale's fictional range, or "".
func (l Locale) Phone(w *World) string { return l.phone(w) }

// EmailLocal is first.last for an address: lower case, ASCII, no spaces.
func EmailLocal(first, last string) string {
	return asciiName(first) + "." + asciiName(last)
}

var transliteration = strings.NewReplacer(
	"ä", "ae", "ö", "oe", "ü", "ue", "Ä", "ae", "Ö", "oe", "Ü", "ue", "ß", "ss",
	"æ", "ae", "Æ", "ae", "ø", "o", "Ø", "o", "å", "a", "Å", "a",
	"é", "e", "è", "e", "ê", "e", "í", "i", "ì", "i", "á", "a", "à", "a", "ó", "o", "ò", "o", "ú", "u",
	"ñ", "n", "ç", "c", "ś", "s", "ł", "l", "ı", "i", "ş", "s", "ğ", "g",
)

func asciiName(s string) string {
	s = transliteration.Replace(s)
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NewDevice returns a typical computer, or phone when mobile is set, of a
// person in city, from the locale's mix of systems.
func (w *World) NewDevice(l Locale, c City, mobile bool) Device {
	d := Device{IP: fmt.Sprintf("%s%d", c.Block, c.Lo+w.Rand.IntN(c.Hi-c.Lo+1)), Country: l.Country}
	const webkit = "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1"
	const chrome = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0"
	switch {
	case mobile && Pick(w, l.MobileOS) == "ios":
		d.Label, d.UserAgent = "Safari on iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) "+webkit+" Mobile/15E148 Safari/604.1"
	case mobile:
		model := Pick(w, []string{"SM-S931B", "Pixel 9", "CPH2581", "SM-A556E", "2312DRA50I"})
		d.Label, d.UserAgent = "Chrome on Android", "Mozilla/5.0 (Linux; Android 15; "+model+") "+chrome+" Mobile Safari/537.36"
	default:
		switch Pick(w, l.DesktopOS) {
		case "mac":
			d.Label, d.UserAgent = "Chrome on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+chrome+" Safari/537.36"
			if w.Chance(0.35) {
				d.Label, d.UserAgent = "Safari on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+webkit+" Safari/605.1.15"
			}
		case "linux":
			d.Label, d.UserAgent = "Firefox on Linux", "Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0"
		default:
			d.Label, d.UserAgent = "Chrome on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+chrome+" Safari/537.36"
			if w.Chance(0.4) {
				d.Label, d.UserAgent = "Edge on Windows", d.UserAgent+" Edg/153.0.0.0"
			}
		}
	}
	return d
}

// Attackers are the sources of credential stuffing and password spraying,
// outside every office range.
var Attackers = []Device{
	{Label: "python-requests", IP: "203.0.113.241", Country: "RU", UserAgent: "python-requests/2.32.3"},
	{Label: "curl", IP: "203.0.113.247", Country: "CN", UserAgent: "curl/8.9.1"},
	{Label: "Headless Chrome", IP: "192.0.2.249", Country: "BR",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36"},
	{Label: "Go HTTP client", IP: "198.51.100.252", Country: "VN", UserAgent: "Go-http-client/2.0"},
}
