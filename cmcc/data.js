window.CONCORDANCE_DATA = {
  meta: {
    title: "The Cormac McCarthy Concordance",
    subtitle: "Persons, places, dates, and crossings",
    updated: "29 August 2026",
    notice: "Contains plot details and endings.",
    sourceNote: "References were checked against the supplied EPUB editions. All the Pretty Horses preserves print-page anchors; the other two EPUBs provide Part and section references but no stable pagination."
  },

  books: [
    { id: "oph", title: "The Orchard Keeper", year: 1965, indexed: false },
    { id: "od", title: "Outer Dark", year: 1968, indexed: false },
    { id: "cog", title: "Child of God", year: 1973, indexed: false },
    { id: "sut", title: "Suttree", year: 1979, indexed: false },
    { id: "bm", title: "Blood Meridian", year: 1985, indexed: false },
    {
      id: "atph", title: "All the Pretty Horses", year: 1992, indexed: true,
      period: "c. 1949–1950", sections: "Parts I–IV", referenceSystem: "Part and print page",
      edition: "Knopf Doubleday EPUB, ISBN 978-0-307-48130-6"
    },
    {
      id: "crossing", title: "The Crossing", year: 1994, indexed: true,
      period: "late 1930s–1945", sections: "Parts I–IV; eleven EPUB sections", referenceSystem: "Part and EPUB section",
      edition: "Alfred A. Knopf EPUB; supplied file has no print-page map"
    },
    {
      id: "cities", title: "Cities of the Plain", year: 1998, indexed: true,
      period: "principally 1952; epilogue c. 2001", sections: "Parts I–IV; twelve EPUB sections", referenceSystem: "Part and EPUB section",
      edition: "Alfred A. Knopf EPUB; supplied file has no print-page map"
    },
    { id: "ncfom", title: "No Country for Old Men", year: 2005, indexed: false },
    { id: "road", title: "The Road", year: 2006, indexed: false },
    { id: "passenger", title: "The Passenger", year: 2022, indexed: false },
    { id: "sm", title: "Stella Maris", year: 2022, indexed: false }
  ],

  characters: [
    {
      id: "john-grady-cole", name: "John Grady Cole", aliases: ["John Grady", "John Cole"], kind: "person", prominence: "principal",
      books: ["atph", "cities"], dates: ["born c. 1933", "1949–1952"],
      locations: ["San Angelo, Texas", "La Purísima, Coahuila", "Saltillo", "Orogrande, New Mexico", "Ciudad Juárez"],
      description: "A gifted horseman and the central figure of All the Pretty Horses. He later works at Mac McGovern’s Cross Fours ranch and pursues Magdalena in Cities of the Plain.",
      references: [
        { book: "atph", locator: "Part I, pp. 3–7", note: "Opening at the Grady ranch" },
        { book: "atph", locator: "Part II, pp. 97–152", note: "La Purísima" },
        { book: "cities", locator: "Part I, §1", note: "At the Cross Fours and in Juárez" },
        { book: "cities", locator: "Part IV, §1", note: "Final confrontation" }
      ]
    },
    {
      id: "lacey-rawlins", name: "Lacey Rawlins", aliases: ["Rawlins"], kind: "person", prominence: "principal",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["San Angelo, Texas", "Coahuila", "Encantada", "Saltillo"],
      description: "John Grady’s friend and traveling companion. More cautious and sardonic than John Grady, he returns to Texas after their imprisonment.",
      references: [
        { book: "atph", locator: "Part I, pp. 26–29", note: "Departure from Texas" },
        { book: "atph", locator: "Part III, pp. 153–218", note: "Arrest and imprisonment" }
      ]
    },
    {
      id: "jimmy-blevins", name: "Jimmy Blevins", aliases: ["Blevins"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1949"], locations: ["Texas–Mexico borderlands", "Encantada"],
      description: "A young runaway who joins John Grady and Rawlins. His disputed horse, pistol, and return to Encantada set the novel’s catastrophe in motion.",
      references: [
        { book: "atph", locator: "Part I, pp. 43–96", note: "Joins the riders and loses his horse" },
        { book: "atph", locator: "Part III, pp. 171–181", note: "Held in Encantada" }
      ]
    },
    {
      id: "alejandra-rocha", name: "Alejandra Rocha", aliases: ["Alejandra"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima, Coahuila", "Mexico City", "Zacatecas"],
      description: "Don Héctor’s daughter, Alfonsa’s grandniece and goddaughter, and John Grady’s lover.",
      references: [
        { book: "atph", locator: "Part II, p. 119", note: "Named at La Purísima" },
        { book: "atph", locator: "Part IV, pp. 245–256", note: "Meeting in Zacatecas" }
      ]
    },
    {
      id: "alfonsa", name: "Alfonsa", aliases: ["Dueña Alfonsa", "Señorita Alfonsa"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["Mexican Revolution recalled", "c. 1950"], locations: ["La Purísima", "Mexico City", "Europe", "London"],
      description: "Alejandra’s grandaunt and godmother. Her revolutionary memories, family authority, and understanding of social consequence shape the lovers’ fate.",
      references: [
        { book: "atph", locator: "Part II, pp. 132–147", note: "Chess and first conversation" },
        { book: "atph", locator: "Part IV, pp. 228–242", note: "Family history and decision" }
      ]
    },
    {
      id: "don-hector", name: "Don Héctor Rocha y Villareal", aliases: ["Don Héctor", "the hacendado"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima, Coahuila", "Mexico City"],
      description: "Owner of La Purísima, Alejandra’s father, and an accomplished horse breeder who recognizes John Grady’s ability.",
      references: [
        { book: "atph", locator: "Part II, p. 97", note: "La Purísima introduced" },
        { book: "atph", locator: "Part II, pp. 112–131", note: "John Grady works with the stallion" }
      ]
    },
    {
      id: "emilio-perez", name: "Emilio Pérez", aliases: ["Pérez"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["Saltillo prison"],
      description: "A polished prison power broker who explains the institution’s economy of protection and violence to John Grady.",
      references: [{ book: "atph", locator: "Part III, pp. 186–193", note: "Meeting in Saltillo prison" }]
    },
    {
      id: "encantada-captain", name: "The captain", aliases: ["Mexican captain", "the madrina"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["Encantada"],
      description: "The corrupt local authority who interrogates John Grady and Rawlins and controls Blevins’s fate.",
      references: [{ book: "atph", locator: "Part III, pp. 162–181", note: "Interrogations and transport" }]
    },
    {
      id: "john-gradys-father", name: "John Grady’s father", aliases: ["Mr Cole", "John Grady’s father"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["Second World War", "dies c. 1950"], locations: ["San Angelo", "San Antonio", "San Diego"],
      description: "An ailing Second World War veteran, separated from John Grady’s mother. His knife later passes to his son.",
      references: [{ book: "atph", locator: "Part I, pp. 5–14", note: "Conversations in San Angelo" }]
    },
    {
      id: "john-gradys-mother", name: "John Grady’s mother", aliases: ["Mrs Cole", "John Grady’s mother"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo", "San Antonio"],
      description: "An actress who inherits and chooses to sell the family ranch, precipitating John Grady’s departure.",
      references: [{ book: "atph", locator: "Part I, pp. 8–25", note: "Ranch inheritance and sale" }]
    },
    {
      id: "franklin", name: "Franklin", aliases: ["Mr Franklin"], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo"],
      description: "The family lawyer whom John Grady consults in an unsuccessful attempt to prevent the ranch’s sale.",
      references: [{ book: "atph", locator: "Part I, pp. 16–17", note: "Legal consultation" }]
    },
    {
      id: "abuela", name: "Abuela", aliases: ["Luisa’s mother"], kind: "unnamed", prominence: "secondary",
      books: ["atph"], dates: ["family service for fifty years", "dies c. 1950"], locations: ["Grady ranch", "Knickerbocker, Texas"],
      description: "The elderly woman who cared for generations of the Grady family and whom John Grady calls his grandmother.",
      references: [
        { book: "atph", locator: "Part I, p. 25", note: "Family history" },
        { book: "atph", locator: "Part IV, pp. 299–301", note: "Death and burial" }
      ]
    },
    {
      id: "luisa", name: "Luisa", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["Grady ranch", "San Angelo"],
      description: "A longtime member of the Grady household and Abuela’s daughter.",
      references: [{ book: "atph", locator: "Part I, pp. 10–18", note: "At the Grady ranch" }]
    },
    {
      id: "arturo", name: "Arturo", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["Grady ranch", "San Angelo"],
      description: "A worker at the Grady ranch and member of its dwindling household.",
      references: [{ book: "atph", locator: "Part I, pp. 4–18", note: "At the Grady ranch" }]
    },
    {
      id: "antonio-atph", name: "Antonio", aliases: ["Armando’s brother"], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima", "Kentucky", "Tennessee", "Texas"],
      description: "Armando’s brother, remembered for transporting Don Héctor’s American stallion from Kentucky to Mexico.",
      references: [{ book: "atph", locator: "Part II, p. 126", note: "Journey with the stallion" }]
    },
    {
      id: "armando", name: "Armando", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A senior horseman at La Purísima who reports John Grady’s abilities to Don Héctor.",
      references: [{ book: "atph", locator: "Part II, pp. 100–131", note: "Horse work at La Purísima" }]
    },
    {
      id: "maria-atph", name: "María", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A member of the household staff at La Purísima, frequently associated with the kitchen and meals.",
      references: [{ book: "atph", locator: "Part II, pp. 112–132", note: "Household scenes" }]
    },
    {
      id: "carlos-atph", name: "Carlos", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A servant in Don Héctor and Alfonsa’s household.",
      references: [{ book: "atph", locator: "Part II, pp. 129–143", note: "Household and billiard-room scenes" }]
    },
    {
      id: "roberto-atph", name: "Roberto", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima", "local dance"],
      description: "A young ranch worker who attends the local dance with John Grady and Rawlins.",
      references: [{ book: "atph", locator: "Part II, pp. 122–125", note: "Dance" }]
    },
    {
      id: "esteban-atph", name: "Estéban", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "An elderly stable worker at La Purísima.",
      references: [{ book: "atph", locator: "Part II, pp. 139–150", note: "Stable scenes" }]
    },
    {
      id: "mary-catherine", name: "Mary Catherine", aliases: [], kind: "person", prominence: "minor",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo"],
      description: "John Grady’s former girlfriend, encountered shortly before he leaves Texas.",
      references: [{ book: "atph", locator: "Part I, p. 28", note: "Brief conversation" }]
    },
    {
      id: "ozona-judge", name: "The Ozona judge", aliases: ["the judge"], kind: "unnamed", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["Ozona, Texas"],
      description: "The judge who hears John Grady’s horse-ownership case and later receives his confession and doubts.",
      references: [{ book: "atph", locator: "Part IV, pp. 288–294", note: "Hearing and evening conversation" }]
    },
    {
      id: "gustavo-madero", name: "Gustavo A. Madero", aliases: ["Gustavo"], kind: "historical", prominence: "secondary",
      books: ["atph"], dates: ["Mexican Revolution", "died 1913"], locations: ["Mexico", "Europe"],
      description: "Historical revolutionary and Alfonsa’s youthful love, recalled in her account of the Madero family and the revolution.",
      references: [{ book: "atph", locator: "Part IV, pp. 233–239", note: "Alfonsa’s recollection" }]
    },
    {
      id: "francisco-madero", name: "Francisco I. Madero", aliases: ["Francisco Madero", "Francisco"], kind: "historical", prominence: "secondary",
      books: ["atph"], dates: ["Mexican Revolution", "president 1911–1913"], locations: ["Coahuila", "Mexico City"],
      description: "Historical president and revolutionary, remembered by Alfonsa as a family friend and tragic idealist.",
      references: [{ book: "atph", locator: "Part IV, pp. 233–239", note: "Alfonsa’s recollection" }]
    },

    {
      id: "billy-parham", name: "Billy Parham", aliases: ["Billy", "Mr Parham"], kind: "person", prominence: "principal",
      books: ["crossing", "cities"], dates: ["born c. 1925", "late 1930s–c. 2001"],
      locations: ["Hidalgo County, New Mexico", "Chihuahua", "Sonora", "Orogrande", "El Paso", "De Baca County"],
      description: "The central figure of The Crossing and an older mentor to John Grady in Cities of the Plain. His life stretches from the border country before the war into the new millennium.",
      references: [
        { book: "crossing", locator: "Part I, §1", note: "Family ranch and the wolf" },
        { book: "crossing", locator: "Part IV, §4", note: "Return toward New Mexico" },
        { book: "cities", locator: "Part I, §1", note: "Cross Fours ranch" },
        { book: "cities", locator: "Part IV, §3", note: "Epilogue" }
      ]
    },
    {
      id: "boyd-parham", name: "Boyd Parham", aliases: ["Boyd"], kind: "person", prominence: "principal",
      books: ["crossing", "cities"], dates: ["born c. 1927", "dies during the 1940s"],
      locations: ["Hidalgo County, New Mexico", "Chihuahua", "Babícora", "San Buenaventura", "De Baca County"],
      description: "Billy’s younger brother, a gifted horseman whose reputation in Mexico becomes partly inseparable from story and legend.",
      references: [
        { book: "crossing", locator: "Part I, §1", note: "Childhood in New Mexico" },
        { book: "crossing", locator: "Parts II–III", note: "Journey for the stolen horses" },
        { book: "cities", locator: "Part IV, §3", note: "Billy remembers Boyd" }
      ]
    },
    {
      id: "mr-parham", name: "Mr Parham", aliases: ["Pap", "Billy’s father", "Boyd’s father"], kind: "unnamed", prominence: "major",
      books: ["crossing"], dates: ["late 1930s"], locations: ["Hidalgo County, New Mexico", "Animas Valley"],
      description: "Billy and Boyd’s father, a rancher who teaches Billy trapping and sends him for advice about the marauding wolf.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Family ranch and wolf traps" }]
    },
    {
      id: "mrs-parham", name: "Mrs Parham", aliases: ["Mama", "Billy’s mother", "Boyd’s mother"], kind: "unnamed", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s"], locations: ["Hidalgo County, New Mexico"],
      description: "Billy and Boyd’s mother, present in the family’s life before the brothers’ first separate journeys.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Parham household" }]
    },
    {
      id: "she-wolf", name: "The she-wolf", aliases: ["the wolf", "loba"], kind: "animal", prominence: "major",
      books: ["crossing"], dates: ["late 1930s"], locations: ["Animas Valley", "Sonora", "Sierra de la Madera"],
      description: "The pregnant Mexican wolf Billy traps and attempts to return across the border, becoming the center of the novel’s first crossing.",
      references: [{ book: "crossing", locator: "Part I, §§1–2", note: "Trapping and journey into Mexico" }]
    },
    {
      id: "the-indian-crossing", name: "The Indian", aliases: ["the old Indian"], kind: "unnamed", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s"], locations: ["Hidalgo County", "river tank near the Parham ranch"],
      description: "An itinerant Indigenous man encountered by Boyd and later sheltered near the Parham ranch.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Encounter at the water" }]
    },
    {
      id: "mr-sanders", name: "Mr Sanders", aliases: ["Sanders"], kind: "person", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s"], locations: ["SK Bar ranch", "Animas Valley"],
      description: "An elderly neighboring rancher who advises the Parhams about the wolf and gives Billy access to Echols’s supplies.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Consultations at the SK Bar" }]
    },
    {
      id: "mr-echols", name: "Mr Echols", aliases: ["old man Echols"], kind: "person", prominence: "secondary",
      books: ["crossing"], dates: ["before the opening journey"], locations: ["Animas Valley", "Echols’s cabin"],
      description: "An absent master trapper whose cabin, traps, and knowledge remain important to Billy’s pursuit of the wolf.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Cabin and trapping materials" }]
    },
    {
      id: "the-mormon", name: "The Mormon", aliases: ["the former Mormon"], kind: "unnamed", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s or early 1940s"], locations: ["northern Mexico"],
      description: "A former Mormon who feeds Billy and offers an extended meditation on God, suffering, and witness.",
      references: [{ book: "crossing", locator: "Part II, §1", note: "Shelter and conversation" }]
    },
    {
      id: "john-gilchrist", name: "John Gilchrist", aliases: ["Gilchrist"], kind: "person", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["New Mexico ranch country"],
      description: "A ranchman connected with Billy’s work after his return from the first Mexican journey.",
      references: [{ book: "crossing", locator: "Part II, §1", note: "Billy asks after Gilchrist" }]
    },
    {
      id: "mr-boruff", name: "Mr Boruff", aliases: ["Boruff"], kind: "person", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["New Mexico"],
      description: "A rancher or foreman whose knowledge of the country is invoked when Billy and Boyd are sighted as distant riders.",
      references: [{ book: "crossing", locator: "Part II, §1", note: "Ranch encounter" }]
    },
    {
      id: "senor-soto", name: "Señor Soto", aliases: ["Soto"], kind: "person", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Casas Grandes"],
      description: "A livestock broker whom Billy seeks while investigating the stolen Parham horses.",
      references: [{ book: "crossing", locator: "Part II, §2", note: "Search in Casas Grandes" }]
    },
    {
      id: "quijada", name: "Quijada", aliases: [], kind: "person", prominence: "major",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Nahuerichic", "Babícora", "Boquilla"],
      description: "Superintendent of the Nahuerichic for Mr Simmons. He helps the brothers identify and cut out horses and later speaks with Billy about Boyd and the estate.",
      references: [
        { book: "crossing", locator: "Part III, §1", note: "Introduces himself and assists with horses" },
        { book: "crossing", locator: "Part IV, §3", note: "Later conversation with Billy" }
      ]
    },
    {
      id: "munoz-woman", name: "The Muñoz woman", aliases: ["Señora Muñoz"], kind: "unnamed", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Babícora domicilios"],
      description: "A woman who shelters the brothers and helps care for the wounded Boyd.",
      references: [{ book: "crossing", locator: "Part III, §§1–3", note: "Shelter and treatment" }]
    },
    {
      id: "blind-revolutionary", name: "The blind revolutionary", aliases: ["the blind man"], kind: "unnamed", prominence: "major",
      books: ["crossing"], dates: ["Mexican Revolution recalled", "early 1940s"], locations: ["Durango", "Mexican borderlands"],
      description: "A former revolutionary whose long account of violence, blindness, fate, and history interrupts the brothers’ journey.",
      references: [{ book: "crossing", locator: "Part III, §2", note: "Revolutionary narrative" }]
    },
    {
      id: "wirtz", name: "Wirtz", aliases: ["Captain Wirtz"], kind: "historical", prominence: "secondary",
      books: ["crossing"], dates: ["Mexican Revolution"], locations: ["Durango"],
      description: "A German Huertista captain in the blind revolutionary’s account, responsible for brutal treatment of prisoners.",
      references: [{ book: "crossing", locator: "Part III, §2", note: "Story of the revolution" }]
    },
    {
      id: "gasparito", name: "Gasparito", aliases: [], kind: "person", prominence: "minor",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Babícora"],
      description: "A drunken mule handler whose misadventure is recounted by the workers.",
      references: [{ book: "crossing", locator: "Part III, §1", note: "Workers’ story" }]
    },
    {
      id: "socorro-rivera", name: "Socorro Rivera", aliases: [], kind: "historical", prominence: "secondary",
      books: ["crossing"], dates: ["killed five years before Billy’s later visit"], locations: ["Las Varitas", "Babícora"],
      description: "A labor organizer killed with Crecencio Macias and Manuel Jiménez by the Guardias Blancas; his story frames the estate’s violence.",
      references: [{ book: "crossing", locator: "Part IV, §3", note: "Quijada’s account" }]
    },
    {
      id: "william-randolph-hearst", name: "William Randolph Hearst", aliases: ["Mr Hearst", "Señor Hearst"], kind: "historical", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Babícora", "Chihuahua"],
      description: "The historical American owner associated with the immense Babícora estate and its conflict with campesinos.",
      references: [
        { book: "crossing", locator: "Part II, §2", note: "Babícora identified" },
        { book: "crossing", locator: "Part IV, §3", note: "Quijada discusses the latifundio" }
      ]
    },
    {
      id: "alfonso-crossing", name: "Alfonso", aliases: [], kind: "person", prominence: "minor",
      books: ["crossing"], dates: ["1940s"], locations: ["Mexico"],
      description: "A grave and drunken man encountered by Billy in a bar during his later travels.",
      references: [{ book: "crossing", locator: "Part IV, §2", note: "Barroom encounter" }]
    },
    {
      id: "gypsy-chief", name: "The gypsy", aliases: ["the gypsy chief", "the drover"], kind: "unnamed", prominence: "major",
      books: ["crossing"], dates: ["1945"], locations: ["Mexican borderlands", "river woods"],
      description: "Leader of a group of gypsy drovers who gives Billy a long meditation on objects, memory, representation, and the world.",
      references: [{ book: "crossing", locator: "Part IV, §4", note: "Conversation beside the dead airplane" }]
    },
    {
      id: "rafael-crossing", name: "Rafael", aliases: [], kind: "person", prominence: "minor",
      books: ["crossing"], dates: ["1945"], locations: ["Mexican borderlands"],
      description: "One of the gypsy drovers accompanying the group’s leader.",
      references: [{ book: "crossing", locator: "Part IV, §4", note: "Gypsy camp" }]
    },
    {
      id: "boyds-companion", name: "Boyd’s companion", aliases: ["the girl", "Boyd’s girl"], kind: "unnamed", prominence: "major",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Chihuahua", "San Buenaventura"],
      description: "The unnamed young woman associated with Boyd during his later life in Mexico and with the stories told about him.",
      references: [{ book: "crossing", locator: "Parts III–IV", note: "Boyd’s later life and aftermath" }]
    },
    {
      id: "bird", name: "Bird", aliases: [], kind: "animal", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s"], locations: ["Parham ranch", "Animas Valley"],
      description: "One of the Parham horses, ridden by Billy during the wolf hunt.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Wolf hunt" }]
    },
    {
      id: "nino", name: "Niño", aliases: ["the Niño horse"], kind: "animal", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["New Mexico", "Chihuahua", "Babícora"],
      description: "A Parham horse sought by Billy and Boyd after the raid on their family ranch.",
      references: [{ book: "crossing", locator: "Parts II–III", note: "Search and recovery attempt" }]
    },
    {
      id: "keno", name: "Keno", aliases: [], kind: "animal", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Chihuahua"],
      description: "A horse ridden and cared for during the brothers’ second Mexican journey.",
      references: [{ book: "crossing", locator: "Part II, §§1–2", note: "Journey south" }]
    },

    {
      id: "mac-mcgovern", name: "Mac McGovern", aliases: ["Mac", "McGovern"], kind: "person", prominence: "major",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Orogrande, New Mexico", "Las Cruces"],
      description: "Owner of the Cross Fours ranch and employer of John Grady, Billy, and the other cowboys. He faces the ranch’s impending military acquisition.",
      references: [
        { book: "cities", locator: "Part I, §§1–3", note: "Life at the Cross Fours" },
        { book: "cities", locator: "Part III, §3", note: "Cabin and ranch plans" }
      ]
    },
    {
      id: "magdalena", name: "Magdalena", aliases: [], kind: "person", prominence: "principal",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez", "White Lake", "riverside south of El Paso"],
      description: "A young epileptic sex worker in Juárez whom John Grady hopes to marry and bring across the border.",
      references: [
        { book: "cities", locator: "Part I, §3", note: "She gives John Grady her name" },
        { book: "cities", locator: "Part III, §3", note: "Attempted escape" }
      ]
    },
    {
      id: "eduardo", name: "Eduardo", aliases: ["the pimp", "the alcahuete"], kind: "person", prominence: "major",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez", "White Lake"],
      description: "Magdalena’s controlling pimp and John Grady’s antagonist, cultivated in manner and ruthless in possession.",
      references: [
        { book: "cities", locator: "Part I, §4", note: "Introduced at the White Lake" },
        { book: "cities", locator: "Part IV, §1", note: "Confrontation" }
      ]
    },
    {
      id: "tiburcio", name: "Tiburcio", aliases: [], kind: "person", prominence: "major",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez", "White Lake", "Rio Grande"],
      description: "Eduardo’s associate and enforcer, involved in watching Magdalena and preventing her escape.",
      references: [
        { book: "cities", locator: "Part I, §4", note: "Reports to Eduardo" },
        { book: "cities", locator: "Part III, §3", note: "Intercepts Magdalena" }
      ]
    },
    {
      id: "oren", name: "Oren", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Orogrande"],
      description: "An experienced cowboy at the Cross Fours, often responsible for practical work and decisions around the ranch.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Breakfast and ranch work" }]
    },
    {
      id: "troy", name: "Troy", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["Second World War veteran", "1952"], locations: ["Cross Fours ranch", "El Paso", "Ciudad Juárez"],
      description: "A Cross Fours cowboy, veteran, and companion in the ranch hands’ excursions and conversations.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Juárez and the Cross Fours" }]
    },
    {
      id: "jc", name: "JC", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Ciudad Juárez"],
      description: "One of the Cross Fours cowboys, associated with the group’s comic stories and ranch work.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Ranch breakfast and recollections" }]
    },
    {
      id: "travis", name: "Travis", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Franklin Mountains"],
      description: "A cowboy and hunter associated with the Cross Fours and the dog-hunting expedition in the Franklins.",
      references: [{ book: "cities", locator: "Parts II–III", note: "Hunt and ranch conversations" }]
    },
    {
      id: "archer", name: "Archer", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["remembers the Mexican Revolution", "1952"], locations: ["El Paso", "Franklin Mountains", "Ciudad Juárez"],
      description: "An older hunter whose memories connect the contemporary borderlands with the 1913 fighting in Juárez.",
      references: [{ book: "cities", locator: "Part II, §1", note: "Fire in the Franklin Mountains" }]
    },
    {
      id: "joaquin", name: "Joaquín", aliases: ["Joaquin"], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Franklin Mountains"],
      description: "A Mexican horseman working at the Cross Fours and participating in the ranch’s handling and hunting work.",
      references: [
        { book: "cities", locator: "Part I, §1", note: "Horse training" },
        { book: "cities", locator: "Part III, §2", note: "Dog hunt" }
      ]
    },
    {
      id: "socorro-cities", name: "Socorro", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch"],
      description: "The cook and domestic center of the Cross Fours household.",
      references: [{ book: "cities", locator: "Part I, §§1–3", note: "Kitchen and household scenes" }]
    },
    {
      id: "mr-johnson", name: "Mr Johnson", aliases: ["Johnson", "old man Johnson"], kind: "person", prominence: "major",
      books: ["cities"], dates: ["born in the nineteenth century", "1952"], locations: ["El Paso", "Las Cruces", "Cross Fours ranch"],
      description: "An elderly lifelong cowboy and Mac’s father-in-law, carrying memories of an older cattle world.",
      references: [
        { book: "cities", locator: "Part I, §1", note: "At the Cross Fours" },
        { book: "cities", locator: "Part II, §2", note: "Night conversation" }
      ]
    },
    {
      id: "margaret-mcgovern", name: "Margaret Johnson McGovern", aliases: ["Margaret"], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["died before 1952"], locations: ["Las Cruces", "Cross Fours ranch"],
      description: "Mr Johnson’s daughter and Mac’s late wife, remembered as an exceptional horsewoman.",
      references: [{ book: "cities", locator: "Part II, §2", note: "Mr Johnson’s recollection" }]
    },
    {
      id: "elton", name: "Elton", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["West Texas ranch country", "Alpine"],
      description: "A rancher and friend visited by John Grady and Billy; his family history includes his brother Johnny’s war experience.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Visit to Elton’s ranch" }]
    },
    {
      id: "ward", name: "Ward", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch"],
      description: "A horseman at the Cross Fours, notably patient while handling a difficult stallion.",
      references: [{ book: "cities", locator: "Part I, §4", note: "Breeding paddock" }]
    },
    {
      id: "wolfenbarger", name: "Wolfenbarger", aliases: [], kind: "person", prominence: "minor",
      books: ["cities"], dates: ["1952"], locations: ["New Mexico"],
      description: "A prospective horse buyer discussed by Mac and the ranch hands.",
      references: [{ book: "cities", locator: "Part II, §1", note: "Horse sale" }]
    },
    {
      id: "blind-maestro", name: "The blind maestro", aliases: ["the maestro"], kind: "unnamed", prominence: "major",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez", "White Lake"],
      description: "A blind musician at the White Lake who speaks with John Grady about Magdalena, beauty, fate, and Eduardo.",
      references: [{ book: "cities", locator: "Part II, §1", note: "Conversation at the White Lake" }]
    },
    {
      id: "josefina", name: "Josefina", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez", "White Lake"],
      description: "An older woman in the White Lake household who supervises Magdalena’s preparation and appearance.",
      references: [{ book: "cities", locator: "Part II, §1", note: "Magdalena’s room" }]
    },
    {
      id: "la-tuerta", name: "La Tuerta", aliases: ["the one-eyed criada"], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez"],
      description: "A one-eyed servant who carries messages and assists Magdalena in attempting to leave.",
      references: [
        { book: "cities", locator: "Part II, §1", note: "Hotel message" },
        { book: "cities", locator: "Part III, §3", note: "Escape attempt" }
      ]
    },
    {
      id: "ramon-cities", name: "Ramón", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Ciudad Juárez"],
      description: "An intermediary involved in the proposed papers and arrangements for Magdalena’s escape.",
      references: [{ book: "cities", locator: "Part III, §3", note: "Escape arrangements" }]
    },
    {
      id: "hector-cities", name: "Héctor", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["1952"], locations: ["Cross Fours ranch", "Bell Springs cabin"],
      description: "A ranch worker who helps John Grady prepare the abandoned cabin for Magdalena.",
      references: [{ book: "cities", locator: "Part III, §3", note: "Preparing the cabin" }]
    },
    {
      id: "betty", name: "Betty", aliases: [], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["c. 2001"], locations: ["New Mexico"],
      description: "The woman who gives the elderly Billy shelter and listens when he wakes from a dream of Boyd.",
      references: [{ book: "cities", locator: "Part IV, §3", note: "Epilogue" }]
    },
    {
      id: "the-dream-narrator", name: "The dream narrator", aliases: ["the narrator", "the stranger beneath the overpass"], kind: "unnamed", prominence: "major",
      books: ["cities"], dates: ["c. 2001"], locations: ["El Paso"],
      description: "The enigmatic speaker who recounts and interprets a nested dream to the elderly Billy in the epilogue.",
      references: [{ book: "cities", locator: "Part IV, §3", note: "Conversation beneath the overpass" }]
    },
    {
      id: "billy-sanchez", name: "Billy Sánchez", aliases: [], kind: "person", prominence: "minor",
      books: ["cities"], dates: ["before 1952"], locations: ["Mexico", "New Mexico"],
      description: "A legendary horse trainer invoked by Joaquín as an example of a person whom horses naturally follow.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Joaquín’s observation" }]
    }
  ]
};
