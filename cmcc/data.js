window.CONCORDANCE_DATA = {
  meta: {
    title: "Cormac McCarthy Character Index",
    updated: "30 August 2026",
    notice: "Contains plot details and endings.",
    sourceNote: "References were checked against the supplied EPUB editions. They use chapters, Parts, sessions, or narrative sequence according to each book’s structure, and EPUB sections where no named division is available. Page numbers are omitted because they vary by edition."
  },

  books: [
    {
      id: "oph", title: "The Orchard Keeper", year: 1965, indexed: true,
      period: "from the 1930s into the postwar years", sections: "Parts I–IV; 21 chapters", referenceSystem: "Part and chapter",
      edition: "Vintage / Knopf Doubleday EPUB, ISBN 978-0-307-76250-4"
    },
    {
      id: "od", title: "Outer Dark", year: 1968, indexed: true,
      period: "undated; from a March birth into autumn", sections: "23 unnumbered narrative sections", referenceSystem: "EPUB section",
      edition: "Vintage International / Knopf Doubleday EPUB, ISBN 978-0-307-76249-8"
    },
    {
      id: "cog", title: "Child of God", year: 1973, indexed: true,
      period: "months before April 1965", sections: "Parts I–III; 52 short sections", referenceSystem: "Part and EPUB section",
      edition: "Knopf Doubleday EPUB, ISBN 978-0-307-76248-1"
    },
    {
      id: "sut", title: "Suttree", year: 1979, indexed: true,
      period: "begins in 1951; spans several years", sections: "34 chapters", referenceSystem: "Chapter",
      edition: "Vintage International / Knopf Doubleday EPUB, ISBN 978-0-307-76247-4"
    },
    {
      id: "bm", title: "Blood Meridian", year: 1985, indexed: true,
      period: "1849–1850; final chapter in 1878", sections: "Chapters I–XXIII and epilogue", referenceSystem: "Chapter",
      edition: "Picador EPUB, ISBN 978-1-4472-8946-3"
    },
    {
      id: "atph", title: "All the Pretty Horses", year: 1992, indexed: true,
      period: "c. 1949–1950", sections: "Parts I–IV", referenceSystem: "Part",
      edition: "Knopf Doubleday EPUB, ISBN 978-0-307-48130-6"
    },
    {
      id: "crossing", title: "The Crossing", year: 1994, indexed: true,
      period: "late 1930s–1945", sections: "Parts I–IV; eleven EPUB sections", referenceSystem: "Part and EPUB section",
      edition: "Alfred A. Knopf EPUB"
    },
    {
      id: "cities", title: "Cities of the Plain", year: 1998, indexed: true,
      period: "principally 1952; epilogue c. 2001", sections: "Parts I–IV; twelve EPUB sections", referenceSystem: "Part and EPUB section",
      edition: "Alfred A. Knopf EPUB"
    },
    {
      id: "ncfom", title: "No Country for Old Men", year: 2005, indexed: true,
      period: "1980", sections: "Chapters I–XIII", referenceSystem: "Chapter",
      edition: "ePubLibre EPUB, 2016 edition"
    },
    {
      id: "road", title: "The Road", year: 2006, indexed: true,
      period: "years after an unspecified catastrophe", sections: "Unnumbered continuous narrative", referenceSystem: "Narrative sequence",
      edition: "Picador EPUB, ISBN 978-0-330-47275-3"
    },
    {
      id: "passenger", title: "The Passenger", year: 2022, indexed: true,
      period: "principally 1980, with Alicia's narrative set earlier", sections: "Prologue and Chapters I–X", referenceSystem: "Chapter and narrative strand",
      edition: "Knopf Doubleday EPUB, ISBN 978-0-593-53522-6"
    },
    {
      id: "sm", title: "Stella Maris", year: 2022, indexed: true,
      period: "1972", sections: "Seven recorded sessions", referenceSystem: "Session",
      edition: "Macmillan EPUB, ISBN 978-1-4472-9402-3"
    }
  ],

  characters: [
    {
      id: "ed-tom-bell", name: "Ed Tom Bell", aliases: ["Sheriff Bell", "Bell", "Ed Tom"], kind: "person", prominence: "principal",
      books: ["ncfom"], dates: ["1980", "sheriff since shortly after the Second World War"], locations: ["Terrell County, Texas", "Sanderson", "Eagle Pass", "Odessa"],
      description: "The sheriff of Terrell County and a veteran of the Second World War. He investigates the desert killings and the pursuit of Llewelyn Moss while the chapter-opening monologues record his account of law, violence, family history, and his decision to retire.",
      references: [
        { book: "ncfom", locator: "Chs. I–IV", note: "Opening monologues and the first investigation" },
        { book: "ncfom", locator: "Chs. V–IX", note: "Search for Moss and visits to the crime scenes" },
        { book: "ncfom", locator: "Chs. X–XIII", note: "Family history, retirement, and the final dreams" }
      ]
    },
    {
      id: "llewelyn-moss", name: "Llewelyn Moss", aliases: ["Moss", "Llewelyn"], kind: "person", prominence: "principal",
      books: ["ncfom"], dates: ["thirty-six years old", "Vietnam veteran", "1980"], locations: ["Sanderson", "the desert caldera", "Del Rio", "Eagle Pass", "Piedras Negras", "Van Horn"],
      description: "A welder and Vietnam veteran who finds the remains of a failed drug transaction and takes a case containing several million dollars. His return to bring water to a wounded man allows the people seeking the money to identify and pursue him.",
      references: [
        { book: "ncfom", locator: "Chs. I–III", note: "Discovery of the money and flight from Sanderson" },
        { book: "ncfom", locator: "Chs. IV–VII", note: "Pursuit, wounds, and recovery in Mexico" },
        { book: "ncfom", locator: "Ch. VIII", note: "Journey with the hitchhiker and death at Van Horn" }
      ]
    },
    {
      id: "anton-chigurh", name: "Anton Chigurh", aliases: ["Chigurh"], kind: "person", prominence: "principal",
      books: ["ncfom"], dates: ["1980"], locations: ["West Texas", "Del Rio", "Eagle Pass", "Piedras Negras", "Odessa"],
      description: "A contract killer sent to recover the missing money. He tracks its transponder, kills several people connected with the search, and applies a private rule of necessity and chance to his encounters.",
      references: [
        { book: "ncfom", locator: "Chs. I–III", note: "Escape from custody and pursuit of Moss" },
        { book: "ncfom", locator: "Chs. IV–VII", note: "Hotel attacks, treatment of his wounds, and Carson Wells" },
        { book: "ncfom", locator: "Chs. IX–X", note: "Carla Jean, the automobile collision, and disappearance" }
      ]
    },
    {
      id: "carla-jean-moss", name: "Carla Jean Moss", aliases: ["Carla Jean", "Mrs Moss"], kind: "person", prominence: "major",
      books: ["ncfom"], dates: ["nineteen years old", "1980"], locations: ["Sanderson", "Odessa", "El Paso"],
      description: "Llewelyn Moss’s wife, raised by her grandmother. Moss sends her to Odessa when the pursuit begins; Bell later tries to protect her, and Chigurh confronts her after her husband and grandmother have died.",
      references: [
        { book: "ncfom", locator: "Chs. I–II", note: "Life with Moss and departure from Sanderson" },
        { book: "ncfom", locator: "Chs. V–VIII", note: "Conversations with Bell and Moss’s death" },
        { book: "ncfom", locator: "Ch. IX", note: "Return from the funeral and encounter with Chigurh" }
      ]
    },
    {
      id: "carson-wells", name: "Carson Wells", aliases: ["Wells"], kind: "person", prominence: "major",
      books: ["ncfom"], dates: ["1980", "former Special Forces lieutenant colonel"], locations: ["Houston", "Eagle Pass", "Piedras Negras"],
      description: "A former Special Forces officer hired by the organization that lost the money. He knows Chigurh, finds Moss in a Mexican hospital, and offers to protect him in exchange for the case before Chigurh kills him.",
      references: [
        { book: "ncfom", locator: "Ch. V", note: "Hiring in Houston and meeting with Moss" },
        { book: "ncfom", locator: "Ch. VI", note: "Search in Eagle Pass and Piedras Negras" },
        { book: "ncfom", locator: "Ch. VII", note: "Final conversation with Chigurh" }
      ]
    },
    {
      id: "loretta-bell", name: "Loretta Bell", aliases: ["Loretta", "Mrs Bell"], kind: "person", prominence: "major",
      books: ["ncfom"], dates: ["1980"], locations: ["Sanderson", "the Bell ranch"],
      description: "Ed Tom Bell’s wife. She takes part in his daily routines, discusses his work and retirement with him, and provides the moral and domestic reference point to which his monologues repeatedly return.",
      references: [
        { book: "ncfom", locator: "Chs. II–IV", note: "Home life during the investigation" },
        { book: "ncfom", locator: "Chs. VI–X", note: "Conversations about the case and retirement" },
        { book: "ncfom", locator: "Chs. XI–XIII", note: "Life after Bell leaves office" }
      ]
    },
    {
      id: "ellis-ncfom", name: "Ellis", aliases: ["Uncle Ellis"], kind: "person", prominence: "major",
      books: ["ncfom"], dates: ["elderly in 1980", "former deputy sheriff"], locations: ["the old Bell family house in Texas"],
      description: "Bell’s elderly, disabled uncle and a former lawman. Bell visits him to discuss their family’s history, the killing that left Ellis in a wheelchair, and Bell’s belief that contemporary violence marks a departure from the past.",
      references: [
        { book: "ncfom", locator: "Ch. IX", note: "Bell’s visit and discussion of family history" },
        { book: "ncfom", locator: "Ch. X", note: "Bell reflects on Ellis’s account" }
      ]
    },
    {
      id: "wendell-ncfom", name: "Wendell", aliases: ["Deputy Wendell"], kind: "person", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["Terrell County", "the desert caldera", "Sanderson"],
      description: "One of Bell’s deputies. He accompanies Bell on horseback to the desert crime scene, helps identify Moss’s truck, and assists with the search of the Desert Aire trailer.",
      references: [
        { book: "ncfom", locator: "Ch. III", note: "Ride to the desert crime scene" },
        { book: "ncfom", locator: "Ch. IV", note: "Search of Moss’s trailer and later investigation" }
      ]
    },
    {
      id: "torbert-ncfom", name: "Torbert", aliases: ["Deputy Torbert"], kind: "person", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["Terrell County", "Sanderson", "the desert caldera"],
      description: "A deputy who works closely with Bell on the homicide investigation. He transports evidence, accompanies Bell to the desert, and receives the report explaining the captive-bolt injuries left by Chigurh’s weapon.",
      references: [
        { book: "ncfom", locator: "Ch. II", note: "The abandoned car and first body" },
        { book: "ncfom", locator: "Ch. IV", note: "Desert investigation and forensic report" },
        { book: "ncfom", locator: "Ch. VI", note: "Work in Bell’s office" }
      ]
    },
    {
      id: "sheriff-lamar", name: "Sheriff Lamar", aliases: ["Lamar"], kind: "person", prominence: "secondary",
      books: ["ncfom"], dates: ["1980", "sheriff for more than twenty years"], locations: ["Sonora, Texas", "the county courthouse"],
      description: "The sheriff whose deputy arrests Chigurh. Bell visits Lamar’s courthouse after Chigurh escapes and kills Deputy Haskins, and Bell remains conscious of the loss’s effect on his colleague.",
      references: [
        { book: "ncfom", locator: "Ch. I", note: "Chigurh’s arrest and escape" },
        { book: "ncfom", locator: "Chs. III–IV", note: "Bell’s visit and the investigation" }
      ]
    },
    {
      id: "deputy-haskins", name: "Deputy Haskins", aliases: ["the Haskins boy", "Lamar’s deputy"], kind: "person", prominence: "secondary",
      books: ["ncfom"], dates: ["dies in 1980"], locations: ["the county courthouse in Sonora"],
      description: "Lamar’s young deputy, who brings Chigurh into the station and leaves him handcuffed while telephoning the sheriff. Chigurh strangles him and takes his vehicle and revolver.",
      references: [
        { book: "ncfom", locator: "Ch. I", note: "Arrest of Chigurh and death in the station" },
        { book: "ncfom", locator: "Ch. IV", note: "Bell and Lamar consider the killing" }
      ]
    },
    {
      id: "carla-jeans-grandmother", name: "Carla Jean’s grandmother", aliases: ["Mama", "Carla Jean’s mother"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["elderly", "dies in March 1980"], locations: ["Odessa", "El Paso"],
      description: "The grandmother who raised Carla Jean and whom Carla Jean calls Mama. She travels with her granddaughter to El Paso, inadvertently gives information to one of the men looking for Moss, and dies soon after Moss.",
      references: [
        { book: "ncfom", locator: "Chs. V–VII", note: "Life with Carla Jean in Odessa" },
        { book: "ncfom", locator: "Ch. VIII", note: "Journey to El Paso and Moss’s pursuers" },
        { book: "ncfom", locator: "Ch. IX", note: "Funeral and Carla Jean’s return home" }
      ]
    },
    {
      id: "hitchhiking-girl-ncfom", name: "The hitchhiking girl", aliases: ["the runaway", "the girl with Moss"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["eighteen years old", "1980"], locations: ["Interstate 10", "Van Horn"],
      description: "A young runaway whom Moss picks up while driving west. They travel and eat together before both are killed when Mexican gunmen attack the motel at Van Horn.",
      references: [
        { book: "ncfom", locator: "Ch. VII", note: "Moss meets the hitchhiker" },
        { book: "ncfom", locator: "Ch. VIII", note: "Journey, conversation, and deaths at Van Horn" }
      ]
    },
    {
      id: "wounded-mexican-ncfom", name: "The wounded Mexican", aliases: ["the dying man", "the man asking for water"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["dies in 1980"], locations: ["the desert caldera"],
      description: "A badly wounded survivor of the failed drug transaction. Moss finds him in a truck asking for water; Moss’s decision to return that night with water exposes his vehicle to the men searching the site.",
      references: [{ book: "ncfom", locator: "Ch. I", note: "Moss’s first visit and return to the caldera" }]
    },
    {
      id: "gas-station-proprietor-ncfom", name: "The filling-station proprietor", aliases: ["the proprietor", "the coin-toss man"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["Sheffield, Texas"],
      description: "The proprietor of a rural filling station where Chigurh stops while tracking Moss. Their conversation becomes a coin toss on which Chigurh silently stakes the man’s life.",
      references: [{ book: "ncfom", locator: "Ch. II", note: "Conversation and coin toss at the filling station" }]
    },
    {
      id: "desert-aire-clerk", name: "The Desert Aire clerk", aliases: ["the trailer-park clerk", "the woman in the office"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["the Desert Aire trailer park", "Sanderson"],
      description: "The woman in the Desert Aire office. When Chigurh asks where Moss works, she refuses to disclose information about a resident despite his repeated demand.",
      references: [{ book: "ncfom", locator: "Ch. IV", note: "Chigurh’s inquiry at the trailer park" }]
    },
    {
      id: "houston-executive-ncfom", name: "The Houston executive", aliases: ["Wells’s employer", "the man in the Houston office"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["Houston", "a seventeenth-floor office"],
      description: "A representative of the organization that lost the money. He hires Wells to recover it and deal with Chigurh; Chigurh later returns the recovered case to him and proposes a new working relationship.",
      references: [
        { book: "ncfom", locator: "Ch. V", note: "Hiring Carson Wells" },
        { book: "ncfom", locator: "Ch. IX", note: "Meeting with Chigurh" }
      ]
    },
    {
      id: "mexican-gunmen-ncfom", name: "The Mexican gunmen", aliases: ["the Barracuda men", "Moss’s Mexican pursuers"], kind: "unnamed", prominence: "secondary",
      books: ["ncfom"], dates: ["1980"], locations: ["Eagle Pass", "Van Horn", "El Paso"],
      description: "Members of a second group seeking the money. They monitor telephone calls, pursue Moss separately from Chigurh, and carry out the attack at Van Horn in which Moss and the hitchhiker are killed.",
      references: [
        { book: "ncfom", locator: "Chs. IV and VII", note: "Parallel search for Moss" },
        { book: "ncfom", locator: "Ch. VIII", note: "Telephone intercept and Van Horn attack" }
      ]
    },
    {
      id: "agent-mcintyre", name: "Agent McIntyre", aliases: ["McIntyre", "the DEA agent"], kind: "person", prominence: "minor",
      books: ["ncfom"], dates: ["1980"], locations: ["the desert caldera", "Terrell County"],
      description: "A DEA agent who joins Bell and Torbert at the desert crime scene, records the vehicles, weapons, drugs, and missing money, and discusses which agencies will take part in the case.",
      references: [{ book: "ncfom", locator: "Ch. IV", note: "Federal examination of the desert crime scene" }]
    },
    {
      id: "molly-ncfom", name: "Molly", aliases: [], kind: "person", prominence: "minor",
      books: ["ncfom"], dates: ["1980"], locations: ["Bell’s office", "Sanderson"],
      description: "A member of Bell’s office staff who handles calls and later traces the relatives of a Vietnam veteran whom Bell wants to visit.",
      references: [
        { book: "ncfom", locator: "Ch. VI", note: "Work in Bell’s office" },
        { book: "ncfom", locator: "Ch. XI", note: "Search for the veteran’s family" }
      ]
    },
    {
      id: "david-demarco", name: "David DeMarco", aliases: ["DeMarco"], kind: "person", prominence: "secondary",
      books: ["ncfom"], dates: ["high-school student in 1980"], locations: ["Odessa", "the automobile collision"],
      description: "One of the two teenagers who help the injured Chigurh after his automobile collision. He accepts money for his shirt and later takes Chigurh’s abandoned pistol; Bell subsequently questions him about the encounter.",
      references: [
        { book: "ncfom", locator: "Ch. IX", note: "Aid to Chigurh after the collision" },
        { book: "ncfom", locator: "Ch. X", note: "Bell’s questioning about Chigurh and the pistol" }
      ]
    },
    {
      id: "demarcos-friend", name: "DeMarco’s friend", aliases: ["the second teenage boy"], kind: "unnamed", prominence: "minor",
      books: ["ncfom"], dates: ["high-school student in 1980"], locations: ["Odessa", "the automobile collision"],
      description: "The second teenager present after Chigurh’s collision. He helps tie the improvised sling and later gives Bell a fuller account of the money, shirt, and pistol than DeMarco does.",
      references: [
        { book: "ncfom", locator: "Ch. IX", note: "Aid to Chigurh after the collision" },
        { book: "ncfom", locator: "Ch. X", note: "Interview with Bell" }
      ]
    },
    {
      id: "detective-cook", name: "Detective Cook", aliases: ["Cook"], kind: "person", prominence: "minor",
      books: ["ncfom"], dates: ["1980"], locations: ["Odessa"],
      description: "An Odessa detective who links a murder weapon to the pistol taken from Chigurh’s wrecked truck and directs Bell to the officer who investigated the collision.",
      references: [{ book: "ncfom", locator: "Ch. X", note: "Telephone call with Bell about the pistol" }]
    },
    {
      id: "roger-catron", name: "Roger Catron", aliases: ["Catron"], kind: "person", prominence: "minor",
      books: ["ncfom"], dates: ["1980"], locations: ["Odessa"],
      description: "The investigator assigned to the automobile collision involving Chigurh. He supplies Bell with details of the wreck and arranges contact with David DeMarco.",
      references: [{ book: "ncfom", locator: "Ch. X", note: "Bell’s inquiry into Chigurh’s collision" }]
    },
    {
      id: "ford-driver-ncfom", name: "The Ford driver", aliases: ["the man in the trunk", "Bill Wyrick (Bell’s provisional label)"], kind: "unnamed", prominence: "minor",
      books: ["ncfom"], dates: ["dies in 1980"], locations: ["West Texas", "the abandoned Ford"],
      description: "The unidentified motorist Chigurh kills after escaping custody so that he can take the man’s Ford. Bell provisionally calls him Bill Wyrick after finding that name on a bloodstained receipt, then tells Torbert that the identity is unknown.",
      references: [
        { book: "ncfom", locator: "Ch. I", note: "Chigurh takes the Ford" },
        { book: "ncfom", locator: "Ch. II", note: "Bell and Torbert examine the body" }
      ]
    },
    {
      id: "brian-ncfom", name: "Brian", aliases: ["the boy with the beer coat"], kind: "person", prominence: "minor",
      books: ["ncfom"], dates: ["young man in 1980"], locations: ["Eagle Pass"],
      description: "A young man outside a bar who sells Moss his coat after Moss crosses the Rio Grande wounded and underdressed.",
      references: [{ book: "ncfom", locator: "Ch. IV", note: "Moss buys the coat" }]
    },
    {
      id: "bells-daughter", name: "The Bells’ daughter", aliases: ["Bell’s daughter"], kind: "unnamed", prominence: "minor",
      books: ["ncfom"], dates: ["would have been thirty in 1980", "dies in childhood"], locations: ["Bell’s memory"],
      description: "Ed Tom and Loretta Bell’s deceased daughter. Bell says that he still speaks to her inwardly and treats the imagined conversations as a source of moral counsel.",
      references: [{ book: "ncfom", locator: "Ch. X", note: "Bell’s account of speaking with his daughter" }]
    },
    {
      id: "bobby-western", name: "Bobby Western", aliases: ["Robert Western", "Western", "Squire Western", "Bobby"], kind: "person", prominence: "principal",
      books: ["passenger", "sm"], dates: ["born in 1945", "principally 1980"], locations: ["New Orleans", "the Gulf Coast", "Tennessee", "Idaho", "Ibiza"],
      description: "A salvage diver and former racing driver, and Alicia Western’s brother. In The Passenger he is questioned about a submerged aircraft and gradually withdraws from his work and former life; in Stella Maris he is the central subject of Alicia’s family history and attachment.",
      references: [
        { book: "passenger", locator: "Chs. I–III, Bobby narrative", note: "The aircraft dive and its immediate consequences" },
        { book: "passenger", locator: "Chs. IV–VIII, Bobby narrative", note: "Investigation, family history, and departure from New Orleans" },
        { book: "passenger", locator: "Chs. IX–X, Bobby narrative", note: "Later isolation and life abroad" },
        { book: "sm", locator: "Sessions I–VII", note: "Alicia’s accounts of her brother" }
      ]
    },
    {
      id: "alicia-western", name: "Alicia Western", aliases: ["Alice", "the girl"], kind: "person", prominence: "principal",
      books: ["passenger", "sm"], dates: ["born in 1951", "dies in 1972", "twenty years old at Stella Maris"], locations: ["Tennessee", "Chicago", "Stella Maris", "New Orleans"],
      description: "A mathematician and Bobby Western’s sister. The Passenger places episodes from her life beside Bobby’s later narrative; Stella Maris records seven conversations during her voluntary psychiatric admission in 1972.",
      references: [
        { book: "passenger", locator: "Prologue", note: "Death in the woods" },
        { book: "passenger", locator: "Chs. I–IX, Alicia interludes", note: "Conversations with the Kid and scenes from her final period" },
        { book: "passenger", locator: "Chs. V–X, Bobby narrative", note: "Bobby’s memories and family history" },
        { book: "sm", locator: "Sessions I–VII", note: "Recorded conversations with Dr Cohen" }
      ]
    },
    {
      id: "thalidomide-kid", name: "The Thalidomide Kid", aliases: ["the Kid", "Thalidomide Kid"], kind: "person", prominence: "major",
      books: ["passenger", "sm"], dates: ["appears to Alicia from childhood onward"], locations: ["Alicia’s rooms", "hospitals", "the Western family home"],
      description: "The principal figure among Alicia’s recurring hallucinations, identified by his small stature and flipper-like hands. He stages performances with a shifting company of figures and argues with Alicia about memory, death, and what she perceives.",
      references: [
        { book: "passenger", locator: "Chs. I–IX, Alicia interludes", note: "The Kid’s visits and performances" },
        { book: "sm", locator: "Sessions I–VII", note: "Alicia’s account of the Kid" }
      ]
    },
    {
      id: "granellen-western", name: "Granellen", aliases: ["Ellen", "the Westerns’ grandmother"], kind: "person", prominence: "secondary",
      books: ["passenger", "sm"], dates: ["elderly by 1980"], locations: ["Wartburg, Tennessee", "the former family farm"],
      description: "Bobby and Alicia’s maternal grandmother. She receives each of them in Tennessee and preserves the family’s history of removal from land taken for the wartime atomic project.",
      references: [
        { book: "passenger", locator: "Ch. V, Bobby narrative", note: "Bobby’s visit to Granellen" },
        { book: "passenger", locator: "Ch. IX, Alicia interlude", note: "Alicia’s final visit" },
        { book: "sm", locator: "Sessions III–IV", note: "Alicia’s account of her grandmother and family history" }
      ]
    },
    {
      id: "royal", name: "Royal", aliases: ["Uncle Royal"], kind: "person", prominence: "secondary",
      books: ["passenger", "sm"], dates: ["elderly by 1980"], locations: ["Granellen’s house", "Tennessee", "formerly Anderson County"],
      description: "Bobby and Alicia’s maternal uncle, who lives with Granellen in Tennessee. By Bobby’s visit he is half-deaf and cognitively declining; he spends much of the night arguing with the television and has difficulty placing events in time.",
      references: [
        { book: "passenger", locator: "Ch. V, Bobby narrative", note: "Bobby visits Granellen and Royal in Tennessee" },
        { book: "passenger", locator: "Ch. VII, Alicia interlude", note: "Alicia names Royal among the relatives with whom Bobby can discuss her" },
        { book: "sm", locator: "Session V", note: "Alicia’s account of Uncle Royal and the family’s ancestry" }
      ]
    },
    {
      id: "western-father", name: "The Westerns’ father", aliases: ["Bobby and Alicia’s father", "Robert Western’s father"], kind: "unnamed", prominence: "secondary",
      books: ["passenger", "sm"], dates: ["works on the Manhattan Project", "dies of cancer before the principal action"], locations: ["Oak Ridge", "Los Alamos", "Lake Tahoe", "Ciudad Juárez"],
      description: "Bobby and Alicia’s father, a physicist who works on the wartime atomic bomb project. He dies of cancer in Ciudad Juárez after seeking treatment with Laetrile.",
      references: [
        { book: "passenger", locator: "Chs. V and VIII, Bobby narrative", note: "Family recollections, the wartime project, and his death from cancer" },
        { book: "sm", locator: "Sessions I–IV and VI", note: "Alicia’s account of his work, cancer, and death in Mexico" }
      ]
    },
    {
      id: "western-mother", name: "Eleanor Western", aliases: ["Eleanor", "The Westerns’ mother", "Bobby and Alicia’s mother"], kind: "person", prominence: "secondary",
      books: ["passenger", "sm"], dates: ["dies of cancer when Alicia is eleven"], locations: ["Oak Ridge", "Los Alamos", "Tennessee"],
      description: "Bobby and Alicia’s mother. She works at the Y-12 uranium-separation plant during the war and later dies of cancer when Alicia is eleven. Alicia remembers her as religious, socially conventional, and uneasy with her daughter’s intellectual interests and behavior.",
      references: [
        { book: "passenger", locator: "Chs. V and VIII, Bobby narrative", note: "Family recollections, her work at Y-12, and her death from cancer" },
        { book: "sm", locator: "Sessions I–V", note: "Alicia’s account of her mother’s illness and death" }
      ]
    },
    {
      id: "miss-vivian", name: "Miss Vivian", aliases: ["the old lady"], kind: "person", prominence: "secondary",
      books: ["passenger", "sm"], dates: ["appears among Alicia’s hallucinations"], locations: ["Alicia’s rooms", "Granellen’s house"],
      description: "An elderly woman in Alicia’s hallucinatory company, usually described in a hat, veil, and fur stole. Alicia distinguishes her from the Kid’s theatrical acts and treats her with particular concern.",
      references: [
        { book: "passenger", locator: "Chs. I, III, and IX, Alicia interludes", note: "Appearances with the Kid’s company" },
        { book: "sm", locator: "Session IV", note: "Alicia describes Miss Vivian" }
      ]
    },
    {
      id: "oiler-passenger", name: "Oiler", aliases: [], kind: "person", prominence: "major",
      books: ["passenger"], dates: ["1980"], locations: ["New Orleans", "the Gulf of Mexico", "offshore drilling sites"],
      description: "Bobby’s colleague at Taylor’s diving operation and his partner on the submerged-aircraft job. A veteran of the Vietnam War, he later dies during offshore work.",
      references: [
        { book: "passenger", locator: "Ch. I, Bobby narrative", note: "Dive on the submerged JetStar" },
        { book: "passenger", locator: "Ch. III, Bobby narrative", note: "Conversations about the aircraft and the war" },
        { book: "passenger", locator: "Ch. VI, Bobby narrative", note: "Report of Oiler’s death" }
      ]
    },
    {
      id: "kline-passenger", name: "Kline", aliases: [], kind: "person", prominence: "major",
      books: ["passenger"], dates: ["1980"], locations: ["New Orleans", "New York"],
      description: "A private investigator whom Bobby consults after government agents search his rooms and accounts. Kline examines the pressure on Bobby and discusses the institutions and records that make him traceable.",
      references: [
        { book: "passenger", locator: "Chs. VI–VII, Bobby narrative", note: "First consultations about the investigation" },
        { book: "passenger", locator: "Chs. VIII–IX, Bobby narrative", note: "Further inquiries and advice" }
      ]
    },
    {
      id: "john-sheddan", name: "John Sheddan", aliases: ["Long John Sheddan", "Sheddan"], kind: "person", prominence: "major",
      books: ["passenger"], dates: ["dies in 1980"], locations: ["New Orleans", "Knoxville", "the Napoleon House"],
      description: "A dealer in prescription drugs and longtime friend of Bobby. His extended conversations with Bobby concern Alicia, their shared past, and his own failing health.",
      references: [
        { book: "passenger", locator: "Ch. I, Bobby narrative", note: "Conversation at the Napoleon House" },
        { book: "passenger", locator: "Chs. V–VIII, Bobby narrative", note: "Knoxville meetings and later conversations" },
        { book: "passenger", locator: "Chs. IX–X, Bobby narrative", note: "Death and posthumous letter" }
      ]
    },
    {
      id: "borman-passenger", name: "Borman", aliases: [], kind: "person", prominence: "major",
      books: ["passenger"], dates: ["1980"], locations: ["Mississippi", "New Orleans", "the Napoleon House"],
      description: "A friend of Bobby and Red who lives for a time in an isolated trailer. Bobby retrieves him at his family’s request, and their conversations address Bobby’s habits, acquaintances, and retreat from ordinary life.",
      references: [
        { book: "passenger", locator: "Ch. VI, Bobby narrative", note: "Bobby’s visit to the trailer" },
        { book: "passenger", locator: "Chs. VII–VIII, Bobby narrative", note: "Later meetings in New Orleans" }
      ]
    },
    {
      id: "debussy-fields", name: "Debussy Fields", aliases: ["Debussy"], kind: "person", prominence: "secondary",
      books: ["passenger"], dates: ["1980"], locations: ["New Orleans", "Galatoire’s", "the French Quarter"],
      description: "A transgender woman and friend of Bobby who recounts her childhood, transition, marriages, and work. Their meals and conversations also touch on Alicia and Bobby’s tendency to live apart from others.",
      references: [
        { book: "passenger", locator: "Ch. II, Bobby narrative", note: "Lunch at Galatoire’s" },
        { book: "passenger", locator: "Chs. VII–IX, Bobby narrative", note: "Later conversations in New Orleans" }
      ]
    },
    {
      id: "josie-passenger", name: "Josie", aliases: [], kind: "person", prominence: "secondary",
      books: ["passenger"], dates: ["1980"], locations: ["the Seven Seas", "New Orleans"],
      description: "A central figure at the Seven Seas, the bar where Bobby lives and meets friends. She monitors the residents, passes on messages, and helps maintain the bar’s informal community.",
      references: [
        { book: "passenger", locator: "Chs. I and III–V, Bobby narrative", note: "Life at the Seven Seas" },
        { book: "passenger", locator: "Chs. VIII–IX, Bobby narrative", note: "Bobby’s later returns" }
      ]
    },
    {
      id: "janice-passenger", name: "Janice", aliases: ["Jan"], kind: "person", prominence: "secondary",
      books: ["passenger"], dates: ["1980"], locations: ["the Seven Seas", "New Orleans"],
      description: "A bartender at the Seven Seas and one of Bobby’s regular contacts there. She looks after his cat Billy Ray when he leaves New Orleans.",
      references: [
        { book: "passenger", locator: "Chs. III and V–VI, Bobby narrative", note: "Work at the Seven Seas" },
        { book: "passenger", locator: "Chs. VII–VIII, Bobby narrative", note: "Bobby’s absence and Billy Ray" }
      ]
    },
    {
      id: "lou-passenger", name: "Lou", aliases: [], kind: "person", prominence: "secondary",
      books: ["passenger"], dates: ["1980"], locations: ["Taylor’s diving operation", "Belle Chasse"],
      description: "The operations manager at Taylor’s, where Bobby, Oiler, and Red work as divers. He has limited information about the aircraft assignment and later refers Bobby to another offshore job.",
      references: [
        { book: "passenger", locator: "Ch. II, Bobby narrative", note: "Discussion of the JetStar assignment" },
        { book: "passenger", locator: "Ch. VI, Bobby narrative", note: "Bobby’s return to the diving office" }
      ]
    },
    {
      id: "red-passenger", name: "Red", aliases: [], kind: "person", prominence: "secondary",
      books: ["passenger"], dates: ["1980"], locations: ["Taylor’s diving operation", "New Orleans", "Mississippi"],
      description: "A diver at Taylor’s and a friend of Bobby, Oiler, and Borman. He discusses the submerged aircraft with Bobby and helps him locate Borman.",
      references: [
        { book: "passenger", locator: "Ch. I, Bobby narrative", note: "Discussion with Bobby and Oiler" },
        { book: "passenger", locator: "Ch. VI, Bobby narrative", note: "Work at Taylor’s and news of Borman" }
      ]
    },
    {
      id: "billy-ray-passenger", name: "Billy Ray", aliases: ["Bobby’s cat"], kind: "animal", prominence: "minor",
      books: ["passenger"], dates: ["1980"], locations: ["Bobby’s room", "the Seven Seas"],
      description: "Bobby’s cat at the Seven Seas. Janice cares for him during Bobby’s absences.",
      references: [
        { book: "passenger", locator: "Chs. I and III, Bobby narrative", note: "Bobby’s room at the Seven Seas" },
        { book: "passenger", locator: "Chs. V–VI, Bobby narrative", note: "Care during Bobby’s travel" }
      ]
    },
    {
      id: "bathless-grogan", name: "Bathless Grogan", aliases: ["Grogan", "the bathless one"], kind: "person", prominence: "minor",
      books: ["passenger"], dates: ["appears among Alicia’s hallucinations"], locations: ["Alicia’s rooms"],
      description: "A member of the Kid’s hallucinatory company, presented as an Irish singer and dancer whom the Kid calls forward during one of the performances.",
      references: [
        { book: "passenger", locator: "Ch. I, Alicia interlude", note: "Mentioned among the company" },
        { book: "passenger", locator: "Ch. III, Alicia interlude", note: "Song and dance performance" }
      ]
    },
    {
      id: "crandall-passenger", name: "Crandall", aliases: ["the dummy"], kind: "person", prominence: "minor",
      books: ["passenger"], dates: ["known to Alicia from childhood"], locations: ["Alicia’s rooms", "the Kid’s performance"],
      description: "A ventriloquist’s dummy from Alicia’s childhood who appears in one of the Kid’s staged scenes. Alicia recognizes him and recalls having known him when she was six.",
      references: [{ book: "passenger", locator: "Ch. VII, Alicia interlude", note: "Recognition during the staged removal" }]
    },
    {
      id: "dr-michael-cohen", name: "Dr Michael Cohen", aliases: ["Dr Cohen", "Michael"], kind: "person", prominence: "principal",
      books: ["sm"], dates: ["1972"], locations: ["Stella Maris, Black River Falls, Wisconsin"],
      description: "The psychiatrist who conducts the seven recorded sessions with Alicia Western. His questions organize the conversations around her hallucinations, mathematics, family history, and reasons for returning to Stella Maris.",
      references: [{ book: "sm", locator: "Sessions I–VII", note: "Recorded conversations with Alicia" }]
    },
    {
      id: "archatron", name: "The Archatron", aliases: ["the presence"], kind: "unnamed", prominence: "secondary",
      books: ["sm"], dates: ["described during Alicia’s 1972 admission"], locations: ["Alicia’s perceptions", "Stella Maris"],
      description: "A presence Alicia distinguishes from the Kid and his company. She describes it to Cohen as an impersonal and threatening form encountered without ordinary sensory features.",
      references: [
        { book: "sm", locator: "Session IV", note: "Alicia introduces the Archatron" },
        { book: "sm", locator: "Session V", note: "Further discussion of the encounter" }
      ]
    },
    {
      id: "john-wesley-rattner", name: "John Wesley Rattner", aliases: ["John Wesley"], kind: "person", prominence: "principal",
      books: ["oph"], dates: ["adolescence", "from the 1930s into the postwar years"], locations: ["Red Branch, Tennessee", "the orchard", "Mr Eller’s store", "Knoxville"],
      description: "The son of Kenneth and Mildred Rattner. He hunts and traps around Red Branch and becomes attached to Marion Sylder without knowing that Sylder killed his father.",
      references: [
        { book: "oph", locator: "Part II, Chs. 2 and 6", note: "Family history and friendship with Sylder" },
        { book: "oph", locator: "Part III, Ch. 1", note: "Hunting with Warn Pulliam" },
        { book: "oph", locator: "Part IV, Chs. 1 and 9", note: "Sylder’s arrest and John Wesley’s return" }
      ]
    },
    {
      id: "marion-sylder", name: "Marion Sylder", aliases: ["Sylder"], kind: "person", prominence: "principal",
      books: ["oph"], dates: ["from the 1930s into the postwar years"], locations: ["Red Branch, Tennessee", "Atlanta", "Knoxville", "the orchard road"],
      description: "A Red Branch native who transports illegal whiskey. He kills Kenneth Rattner during an attack, conceals the body, and later befriends Rattner’s son John Wesley.",
      references: [
        { book: "oph", locator: "Part I, Chs. 1–2", note: "Return to Red Branch and Kenneth Rattner’s death" },
        { book: "oph", locator: "Part II, Chs. 6–7", note: "Bootlegging and friendship with John Wesley" },
        { book: "oph", locator: "Part IV, Chs. 1, 4, and 7", note: "Investigation, arrest, and imprisonment" }
      ]
    },
    {
      id: "arthur-ownby", name: "Arthur Ownby", aliases: ["Uncle Ather", "the orchard keeper"], kind: "person", prominence: "principal",
      books: ["oph"], dates: ["elderly during the principal action"], locations: ["the abandoned orchard", "Red Branch", "Knoxville"],
      description: "An elderly man who lives near the abandoned orchard and tends the trees. He watches over the spray pit where Sylder has hidden Kenneth Rattner’s body, though he does not know the dead man’s identity.",
      references: [
        { book: "oph", locator: "Part I, Chs. 1–2", note: "Life at the orchard and the spray pit" },
        { book: "oph", locator: "Part IV, Chs. 2–3", note: "The government tank and the search for Ownby" },
        { book: "oph", locator: "Part IV, Chs. 6 and 8", note: "Capture and confinement" }
      ]
    },
    {
      id: "kenneth-rattner", name: "Kenneth Rattner", aliases: ["Kenneth", "Rattner"], kind: "person", prominence: "major",
      books: ["oph"], dates: ["dies before the principal action"], locations: ["Atlanta", "the road to Red Branch", "the orchard spray pit"],
      description: "Mildred’s husband and John Wesley’s father, an itinerant laborer and thief. He attacks Sylder after accepting a ride and is killed in the struggle.",
      references: [
        { book: "oph", locator: "Part I, Ch. 1", note: "Meeting with Sylder and death" },
        { book: "oph", locator: "Part II, Ch. 2", note: "John Wesley’s account of his father" },
        { book: "oph", locator: "Part IV, Chs. 8–9", note: "Discovery and identification of the body" }
      ]
    },
    {
      id: "mildred-rattner", name: "Mildred Rattner", aliases: ["Mildred", "Mrs Rattner"], kind: "person", prominence: "major",
      books: ["oph"], dates: ["from the 1930s into the postwar years"], locations: ["Red Branch, Tennessee", "Akron, Ohio"],
      description: "Kenneth Rattner’s wife and John Wesley’s mother. She raises John Wesley after Kenneth’s disappearance and later leaves Tennessee.",
      references: [
        { book: "oph", locator: "Part I, Ch. 1", note: "Kenneth’s return to the family" },
        { book: "oph", locator: "Part IV, Chs. 1 and 9", note: "John Wesley’s home and the family’s departure" }
      ]
    },
    {
      id: "jefferson-gifford", name: "Jefferson Gifford", aliases: ["Sheriff Gifford", "Gifford"], kind: "person", prominence: "major",
      books: ["oph"], dates: ["during the principal action"], locations: ["Knox County", "Red Branch", "the orchard"],
      description: "The county sheriff who investigates bootlegging in Red Branch. His inquiries connect Sylder’s whiskey runs with Ownby and the body in the orchard.",
      references: [
        { book: "oph", locator: "Part II, Ch. 6", note: "Investigation of Sylder" },
        { book: "oph", locator: "Part III, Ch. 2", note: "Questioning after the automobile wreck" },
        { book: "oph", locator: "Part IV, Chs. 4 and 8", note: "Arrests and the orchard investigation" }
      ]
    },
    {
      id: "warn-pulliam", name: "Warn Pulliam", aliases: ["Warn"], kind: "person", prominence: "secondary",
      books: ["oph"], dates: ["adolescence"], locations: ["Red Branch", "the woods", "Mr Eller’s store"],
      description: "John Wesley’s friend and hunting companion. He is part of the group of local boys who trap, trade, and exchange stories around Red Branch.",
      references: [
        { book: "oph", locator: "Part III, Ch. 1", note: "Hunting and trapping with John Wesley" },
        { book: "oph", locator: "Part IV, Chs. 4 and 7", note: "News of Sylder and the orchard" }
      ]
    },
    {
      id: "mr-eller", name: "Mr Eller", aliases: ["Eller"], kind: "person", prominence: "secondary",
      books: ["oph"], dates: ["during the principal action"], locations: ["Mr Eller’s store", "Red Branch"],
      description: "The proprietor of the Red Branch store where John Wesley, Warn, and other residents gather. His store is a local point of exchange for goods and information.",
      references: [
        { book: "oph", locator: "Part I, Chs. 1–2", note: "The Red Branch store" },
        { book: "oph", locator: "Part III, Ch. 1", note: "John Wesley and the local boys" },
        { book: "oph", locator: "Part IV, Chs. 1, 4, and 7–8", note: "News of the arrests and the body" }
      ]
    },
    {
      id: "june-tipton", name: "June Tipton", aliases: ["June"], kind: "person", prominence: "secondary",
      books: ["oph"], dates: ["during the principal action"], locations: ["Red Branch", "Knoxville", "the bootlegging routes"],
      description: "A member of the Tipton family involved in the local whiskey trade and one of Sylder’s associates.",
      references: [
        { book: "oph", locator: "Part I, Ch. 1", note: "Sylder’s Red Branch connections" },
        { book: "oph", locator: "Part II, Ch. 6", note: "The bootlegging network" },
        { book: "oph", locator: "Part IV, Chs. 6 and 8", note: "Later reports and investigation" }
      ]
    },
    {
      id: "legwater", name: "Legwater", aliases: [], kind: "person", prominence: "secondary",
      books: ["oph"], dates: ["during the principal action"], locations: ["Knox County", "Red Branch", "the orchard road"],
      description: "A milkman who supplies Sheriff Gifford with information about Sylder and the automobile wreck near the orchard.",
      references: [
        { book: "oph", locator: "Part II, Ch. 6", note: "Information given to Gifford" },
        { book: "oph", locator: "Part III, Ch. 2", note: "The wreck investigation" },
        { book: "oph", locator: "Part IV, Ch. 8", note: "The body in the orchard" }
      ]
    },
    {
      id: "scout-and-buster", name: "Scout and Buster", aliases: ["Ownby’s dogs"], kind: "animal", prominence: "secondary",
      books: ["oph"], dates: ["during the principal action"], locations: ["the orchard", "Red Branch woods"],
      description: "Arthur Ownby’s dogs. Scout is his principal companion in the orchard and in the woods; Buster is the other dog kept at his cabin.",
      references: [
        { book: "oph", locator: "Part I, Ch. 2", note: "Ownby’s life at the orchard" },
        { book: "oph", locator: "Part III, Ch. 1", note: "Encounter with the hunting boys" },
        { book: "oph", locator: "Part IV, Chs. 2–3 and 6", note: "Ownby’s flight and capture" }
      ]
    },
    {
      id: "johnny-romines", name: "Johnny Romines", aliases: ["Johnny"], kind: "person", prominence: "minor",
      books: ["oph"], dates: ["adolescence"], locations: ["Red Branch", "the woods"],
      description: "One of the Red Branch boys who hunts and trades with John Wesley and Warn Pulliam.",
      references: [
        { book: "oph", locator: "Part III, Ch. 1", note: "The boys’ hunting expedition" },
        { book: "oph", locator: "Part IV, Ch. 8", note: "Later news in Red Branch" }
      ]
    },
    {
      id: "boog-oph", name: "Boog", aliases: [], kind: "person", prominence: "minor",
      books: ["oph"], dates: ["adolescence"], locations: ["Red Branch", "the woods"],
      description: "A boy in Warn Pulliam’s circle who takes part in the group’s hunting and trapping.",
      references: [{ book: "oph", locator: "Part III, Ch. 1", note: "The boys’ hunting expedition" }]
    },
    {
      id: "ef-hobie", name: "Ef Hobie", aliases: ["Hobie"], kind: "person", prominence: "minor",
      books: ["oph"], dates: ["before and during the principal action"], locations: ["the Green Fly Inn", "Red Branch"],
      description: "A figure associated with the Green Fly Inn and the earlier phase of Red Branch’s whiskey trade.",
      references: [
        { book: "oph", locator: "Part I, Ch. 1", note: "The Green Fly Inn" },
        { book: "oph", locator: "Part II, Ch. 6", note: "Recollections of the bootlegging trade" }
      ]
    },
    {
      id: "man-road", name: "The man", aliases: ["the father", "Papa"], kind: "unnamed", prominence: "principal",
      books: ["road"], dates: ["years after the catastrophe"], locations: ["the road", "the mountains", "the coast"],
      description: "The boy’s father. Ill and increasingly weak, he leads his son south, searches for food and shelter, and tries to keep him apart from the violence of other survivors.",
      references: [
        { book: "road", locator: "Opening narrative", note: "Journey south with the boy" },
        { book: "road", locator: "Middle narrative", note: "The bunker, Ely, and the coastward journey" },
        { book: "road", locator: "Closing narrative", note: "Final illness and death" }
      ]
    },
    {
      id: "boy-road", name: "The boy", aliases: ["the son"], kind: "unnamed", prominence: "principal",
      books: ["road"], dates: ["born after the catastrophe", "childhood"], locations: ["the road", "the mountains", "the coast"],
      description: "The man’s son, born after the catastrophe. His concern for strangers repeatedly tests his father’s rules about danger, charity, and the people they call the good guys.",
      references: [
        { book: "road", locator: "Opening narrative", note: "Travel and the father’s instructions" },
        { book: "road", locator: "Middle narrative", note: "Encounters with Ely and the thief" },
        { book: "road", locator: "Closing narrative", note: "His father’s death and the new family" }
      ]
    },
    {
      id: "mother-road", name: "The mother", aliases: ["the woman", "the man’s wife"], kind: "unnamed", prominence: "major",
      books: ["road"], dates: ["dies before the principal journey"], locations: ["the family home", "the man’s memories"],
      description: "The boy’s mother and the man’s wife. Convinced that capture is inevitable, she leaves the family and dies by suicide before the southward journey.",
      references: [
        { book: "road", locator: "Opening narrative", note: "The man’s memories of her death" },
        { book: "road", locator: "Middle narrative", note: "The boy’s questions about his mother" }
      ]
    },
    {
      id: "ely-road", name: "Ely", aliases: ["the old man", "not Ely"], kind: "person", prominence: "secondary",
      books: ["road"], dates: ["elderly"], locations: ["the road"],
      description: "An old traveler whom the man and boy feed and shelter for a night. He says that Ely is not his real name and speaks with the man about survival and belief.",
      references: [{ book: "road", locator: "Middle narrative", note: "A night on the road with the man and boy" }]
    },
    {
      id: "thief-road", name: "The thief", aliases: ["the cart thief"], kind: "unnamed", prominence: "secondary",
      books: ["road"], dates: ["late in the journey"], locations: ["the coast road"],
      description: "A starving man who takes the travelers’ cart and possessions. The father recovers the goods and makes him surrender his clothes, despite the boy’s objections.",
      references: [{ book: "road", locator: "Late narrative", note: "The theft and recovery of the cart" }]
    },
    {
      id: "road-rat", name: "The road rat", aliases: ["the truck man"], kind: "unnamed", prominence: "secondary",
      books: ["road"], dates: ["early in the journey"], locations: ["a mountain road", "the disabled truck"],
      description: "An armed member of a group traveling by truck. He seizes the boy, and the father shoots him before escaping into the woods.",
      references: [{ book: "road", locator: "Early narrative", note: "Encounter at the disabled truck" }]
    },
    {
      id: "veteran-road", name: "The veteran", aliases: ["the man with the shotgun", "the final man"], kind: "unnamed", prominence: "major",
      books: ["road"], dates: ["after the father’s death"], locations: ["the coast road"],
      description: "An armed survivor traveling with his wife and children. He approaches the boy after the father’s death and offers to take him into the family.",
      references: [{ book: "road", locator: "Closing narrative", note: "The boy joins the family" }]
    },
    {
      id: "veterans-wife-road", name: "The veteran’s wife", aliases: ["the final woman"], kind: "unnamed", prominence: "secondary",
      books: ["road"], dates: ["after the father’s death"], locations: ["the coast road"],
      description: "A woman traveling with the veteran and their children. She welcomes the boy and speaks with him about his father, prayer, and God.",
      references: [{ book: "road", locator: "Closing narrative", note: "The boy’s life with the new family" }]
    },
    {
      id: "burned-man-road", name: "The burned man", aliases: ["the lightning-struck man"], kind: "unnamed", prominence: "minor",
      books: ["road"], dates: ["early in the journey"], locations: ["the road"],
      description: "A badly burned survivor found walking alone. The boy wants to help him, but the father refuses because they have too little food.",
      references: [{ book: "road", locator: "Early narrative", note: "Brief encounter on the road" }]
    },
    {
      id: "cellar-prisoners-road", name: "The cellar prisoners", aliases: ["the captives"], kind: "unnamed", prominence: "secondary",
      books: ["road"], dates: ["during the southward journey"], locations: ["the cellar of a large house"],
      description: "A group of mutilated captives held in a locked cellar by people who use them for food. The man and boy discover them and flee when the owners return.",
      references: [{ book: "road", locator: "Middle narrative", note: "Discovery in the locked cellar" }]
    },
    {
      id: "culla-holme", name: "Culla Holme", aliases: ["Culla", "Holme"], kind: "person", prominence: "principal",
      books: ["od"], dates: ["undated", "from March into autumn"], locations: ["Appalachian South", "the Holme cabin", "Johnson County", "river country", "the swamp road"],
      description: "Rinthy’s brother and the father of her child. He leaves the newborn in the woods, tells Rinthy that it died, and later travels alone, repeatedly encountering the aftermath of killings committed by the three strangers.",
      references: [
        { book: "od", locator: "§§2–4", note: "Birth, abandonment, and departure" },
        { book: "od", locator: "§§5 and 15", note: "Work for the squire and encounter with the three men" },
        { book: "od", locator: "§§21 and 23", note: "The child and the final road" }
      ]
    },
    {
      id: "rinthy-holme", name: "Rinthy Holme", aliases: ["Rinthy"], kind: "person", prominence: "principal",
      books: ["od"], dates: ["nineteen years old", "gives birth in March", "searches through the following months"], locations: ["the Holme cabin", "Appalachian roads and farms", "a country doctor’s office", "the tinker’s camp"],
      description: "Culla’s sister and the child’s mother. After finding the grave empty, she leaves home to search for the infant and follows reports of the tinker’s movements.",
      references: [
        { book: "od", locator: "§§2–4", note: "Birth, empty grave, and decision to leave" },
        { book: "od", locator: "§§7–10", note: "The search along the road" },
        { book: "od", locator: "§§14 and 16", note: "Doctor’s visit and meeting with the tinker" }
      ]
    },
    {
      id: "holme-child", name: "Rinthy’s child", aliases: ["the child", "the baby", "the chap"], kind: "unnamed", prominence: "major",
      books: ["od"], dates: ["born in March", "about six months old at death"], locations: ["the Holme cabin", "the woods", "the tinker’s cart", "the three men’s camp"],
      description: "The infant born to Rinthy and Culla. Culla leaves the child in the woods; the tinker finds and carries it until the three strangers take and kill it.",
      references: [
        { book: "od", locator: "§§2–3", note: "Birth, abandonment, and rescue" },
        { book: "od", locator: "§16", note: "Rinthy sees the child with the tinker" },
        { book: "od", locator: "§21", note: "Death at the strangers’ camp" }
      ]
    },
    {
      id: "tinker-od", name: "The tinker", aliases: ["the peddler", "the chapman"], kind: "unnamed", prominence: "major",
      books: ["od"], dates: ["undated", "spring through autumn"], locations: ["the Holme cabin", "country roads", "river settlements", "the three men’s camp"],
      description: "An itinerant peddler who finds the abandoned infant and carries it in his cart. Rinthy follows reports of his route, which also intersects with Culla and the three strangers.",
      references: [
        { book: "od", locator: "§§2–3", note: "Visits the Holmes and finds the child" },
        { book: "od", locator: "§16", note: "Encounter with Rinthy" },
        { book: "od", locator: "§§20–22", note: "Pursuit and death" }
      ]
    },
    {
      id: "bearded-leader-od", name: "The bearded stranger", aliases: ["the bearded man", "the leader of the three"], kind: "unnamed", prominence: "major",
      books: ["od"], dates: ["undated"], locations: ["the opening glade", "the squire’s road", "a country cabin", "the river", "the final camp"],
      description: "The bearded leader and principal speaker of the three strangers. He questions Culla about the deaths associated with him and directs the group’s actions.",
      references: [
        { book: "od", locator: "§1", note: "First appearance with the other strangers" },
        { book: "od", locator: "§§5 and 12", note: "Killings along the road" },
        { book: "od", locator: "§§15 and 21", note: "Interrogations of Culla" }
      ]
    },
    {
      id: "harmon-od", name: "Harmon", aliases: [], kind: "person", prominence: "major",
      books: ["od"], dates: ["undated"], locations: ["the opening glade", "the squire’s road", "the river", "the final camp"],
      description: "The named, rifle-carrying member of the three strangers. He participates in their pursuit of the tinker and in their encounters with Culla.",
      references: [
        { book: "od", locator: "§§1 and 5", note: "Early appearances and the squire’s death" },
        { book: "od", locator: "§15", note: "At the river camp with Culla" },
        { book: "od", locator: "§21", note: "The child at the final camp" }
      ]
    },
    {
      id: "nameless-mute-od", name: "The nameless mute", aliases: ["the mute", "the third stranger", "the nameless one"], kind: "unnamed", prominence: "major",
      books: ["od"], dates: ["undated"], locations: ["the opening glade", "the road", "the river", "the final camp"],
      description: "The silent member of the three strangers, distinct from Harmon. At the final camp he kills and mutilates Rinthy’s child.",
      references: [
        { book: "od", locator: "§1", note: "First appearance" },
        { book: "od", locator: "§15", note: "At the river camp" },
        { book: "od", locator: "§21", note: "The child’s death" }
      ]
    },
    {
      id: "squire-od", name: "The squire", aliases: ["Culla’s employer"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["undated"], locations: ["a large farm", "the road beyond the farm"],
      description: "A prosperous landowner who hires Culla to clear timber, feeds him, and gives him boots. The three strangers murder him soon after Culla leaves.",
      references: [{ book: "od", locator: "§5", note: "Culla’s employment and the squire’s death" }]
    },
    {
      id: "john-od", name: "John", aliases: ["the squire’s mute worker"], kind: "person", prominence: "secondary",
      books: ["od"], dates: ["undated"], locations: ["the squire’s farm"],
      description: "A mute Black worker on the squire’s farm who helps Culla sharpen an axe and tries by gesture to warn the household of approaching danger.",
      references: [{ book: "od", locator: "§5", note: "Work with Culla and warning at the farm" }]
    },
    {
      id: "old-host-od", name: "The old host", aliases: ["the old bearded man", "Culla’s host"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["undated"], locations: ["a remote cabin"],
      description: "An elderly man who gives Culla food and shelter at his cabin. Their conversation concerns solitude, snakes, illness, and travel.",
      references: [{ book: "od", locator: "§11", note: "Night at the old man’s cabin" }]
    },
    {
      id: "doctor-od", name: "The country doctor", aliases: ["the doctor"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["about six months after the birth"], locations: ["a small town office"],
      description: "A doctor who examines Rinthy and infers that she has recently given birth. His questions lead her to conclude that the infant may still be alive.",
      references: [{ book: "od", locator: "§14", note: "Examination and conversation with Rinthy" }]
    },
    {
      id: "lawyer-od", name: "The lawyer", aliases: [], kind: "unnamed", prominence: "minor",
      books: ["od"], dates: ["about six months after the birth"], locations: ["a small town office"],
      description: "A town lawyer who lets the exhausted Rinthy wait in his office and directs her to the doctor upstairs.",
      references: [{ book: "od", locator: "§14", note: "Rinthy waits in his office" }]
    },
    {
      id: "ferryman-od", name: "The ferryman", aliases: ["the river ferryman"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["undated"], locations: ["a flooded river crossing"],
      description: "The operator who agrees to carry Culla across a flooded river. The ferry breaks loose during the crossing and the ferryman is lost in the river.",
      references: [{ book: "od", locator: "§15", note: "The night ferry crossing" }]
    },
    {
      id: "hog-drover-od", name: "The hog drover", aliases: ["Billy’s brother"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["autumn"], locations: ["mountain roads", "a drovers’ camp"],
      description: "A trader driving hogs through the mountains who hires Culla’s help and travels with his younger brother Billy and a one-eyed preacher.",
      references: [{ book: "od", locator: "§19", note: "The hog drive" }]
    },
    {
      id: "billy-od", name: "Billy", aliases: ["the drover’s little brother"], kind: "person", prominence: "minor",
      books: ["od"], dates: ["autumn", "his first hog drive"], locations: ["mountain roads", "a drovers’ camp"],
      description: "The hog drover’s younger brother, making his first drive and sharing the road and camp with Culla.",
      references: [{ book: "od", locator: "§19", note: "Travel with the hogs" }]
    },
    {
      id: "one-eyed-preacher-od", name: "The one-eyed preacher", aliases: ["the reverend", "the parson"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["autumn"], locations: ["mountain roads", "the drovers’ camp"],
      description: "A one-eyed itinerant preacher who travels with the hog drovers and speaks to Culla about blindness, sin, and spiritual direction.",
      references: [{ book: "od", locator: "§19", note: "Conversation at the drovers’ camp" }]
    },
    {
      id: "blind-man-od", name: "The blind man", aliases: ["the blind traveler"], kind: "unnamed", prominence: "secondary",
      books: ["od"], dates: ["years after the principal events"], locations: ["the swamp road"],
      description: "A traveler whom Culla meets near the end of the novel. He describes a road built into a swamp that has no destination.",
      references: [{ book: "od", locator: "§23", note: "The final meeting on the road" }]
    },
    {
      id: "cornelius-suttree", name: "Cornelius Suttree", aliases: ["Suttree", "Sut", "Cornelius"], kind: "person", prominence: "principal",
      books: ["sut"], dates: ["in Knoxville by 1951", "on the river for several years"], locations: ["Knoxville", "McAnally Flats", "the Tennessee River", "the Smoky Mountains"],
      description: "A fisherman living on a houseboat on the Tennessee River in Knoxville. Estranged from his family, he associates chiefly with residents of McAnally Flats and leaves the city after several years.",
      references: [
        { book: "sut", locator: "Ch. 1", note: "Houseboat, river, and McAnally circle" },
        { book: "sut", locator: "Ch. 10", note: "His son’s death and funeral" },
        { book: "sut", locator: "Chs. 22, 24, and 27", note: "Mountains, Wanda, and Joyce" },
        { book: "sut", locator: "Ch. 34", note: "Illness and departure from Knoxville" }
      ]
    },
    {
      id: "gene-harrogate", name: "Gene Harrogate", aliases: ["Harrogate", "Gene", "City Mouse", "Watermelon Boy"], kind: "person", prominence: "principal",
      books: ["sut"], dates: ["late teens in the early 1950s"], locations: ["Knoxville workhouse", "McAnally Flats", "sewers beneath Knoxville", "Suttree’s houseboat"],
      description: "A young offender whom Suttree meets in the workhouse and later assists in Knoxville. His schemes involve watermelons, poisoned bats, counterfeit coins, and a tunnel beneath the city.",
      references: [
        { book: "sut", locator: "Ch. 3", note: "Workhouse arrival and the watermelon case" },
        { book: "sut", locator: "Chs. 6 and 15", note: "Return to Knoxville and counterfeiting" },
        { book: "sut", locator: "Ch. 20", note: "The tunnel and bat scheme" },
        { book: "sut", locator: "Ch. 34", note: "Final encounters with Suttree" }
      ]
    },
    {
      id: "j-bone", name: "J-Bone", aliases: ["J Bone"], kind: "person", prominence: "major",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "McAnally Flats", "Market Lunch", "the Huddle"],
      description: "A longstanding friend and frequent drinking companion of Suttree. He appears throughout Suttree’s life in Knoxville and meets him shortly before his departure.",
      references: [
        { book: "sut", locator: "Ch. 1", note: "Introduced in Suttree’s riverfront circle" },
        { book: "sut", locator: "Ch. 13", note: "The roadhouse brawl" },
        { book: "sut", locator: "Ch. 34", note: "Last meeting before Suttree leaves" }
      ]
    },
    {
      id: "ab-jones", name: "Ab Jones", aliases: ["Ab"], kind: "person", prominence: "major",
      books: ["sut"], dates: ["early 1950s"], locations: ["McAnally Flats", "Front Street", "Knoxville jail", "the Tennessee River"],
      description: "A Black resident of the riverfront and a friend of Suttree. His continuing conflict with the Knoxville police ends with a severe beating shortly before Suttree leaves the city.",
      references: [
        { book: "sut", locator: "Ch. 7", note: "Ab’s house and riverfront community" },
        { book: "sut", locator: "Chs. 14, 16–17", note: "Conflict, arrest, and return" },
        { book: "sut", locator: "Chs. 33–34", note: "Final confrontation with police" }
      ]
    },
    {
      id: "billy-ray-callahan", name: "Billy Ray Callahan", aliases: ["Callahan", "Billy Ray", "Red Callahan"], kind: "person", prominence: "major",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville workhouse", "McAnally Flats", "the B&J", "the West Inn"],
      description: "A friend of Suttree known for drinking and fighting. He works in the workhouse kitchen, participates in several bar fights, and is shot at the West Inn.",
      references: [
        { book: "sut", locator: "Ch. 3", note: "Workhouse cook and inmate" },
        { book: "sut", locator: "Ch. 13", note: "The roadhouse brawl" },
        { book: "sut", locator: "Ch. 26", note: "Final night and shooting" }
      ]
    },
    {
      id: "reese-sut", name: "Reese", aliases: ["old Reese"], kind: "person", prominence: "major",
      books: ["sut"], dates: ["spring of Suttree’s third year on the river"], locations: ["the Tennessee River", "the mussel-fishing camp", "Knoxville"],
      description: "The head of a family engaged in mussel fishing. He hires Suttree and devotes the expedition to finding freshwater pearls.",
      references: [
        { book: "sut", locator: "Ch. 24", note: "The pearl-hunting expedition" },
        { book: "sut", locator: "Ch. 25", note: "Aftermath of the expedition" }
      ]
    },
    {
      id: "wanda-reese", name: "Wanda Reese", aliases: ["Wanda"], kind: "person", prominence: "major",
      books: ["sut"], dates: ["a teenager in the early 1950s"], locations: ["the Reese camp", "the river islands", "the mussel-fishing country"],
      description: "Reese’s daughter, who begins a secret relationship with Suttree during the pearl expedition and dies when a rockslide strikes the camp.",
      references: [
        { book: "sut", locator: "Ch. 24", note: "Life at the Reese camp" },
        { book: "sut", locator: "Ch. 24", note: "Relationship with Suttree and death" }
      ]
    },
    {
      id: "joyce-sut", name: "Joyce", aliases: [], kind: "person", prominence: "major",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "the Huddle", "a hotel", "Suttree’s houseboat"],
      description: "A sex worker who enters a relationship with Suttree. They live together in hotels and on the houseboat before separating after a period of drinking, jealousy, and violence.",
      references: [{ book: "sut", locator: "Ch. 27", note: "Courtship, extravagant interlude, and separation" }]
    },
    {
      id: "michael-sut", name: "Michael", aliases: ["the Indian", "Tonto", "Wahoo", "Chief"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["the Tennessee River", "Knoxville bars", "Suttree’s houseboat"],
      description: "An Indigenous fisherman who accompanies Suttree on the river and in Knoxville. Other characters usually address him by nicknames before his name is disclosed.",
      references: [
        { book: "sut", locator: "Ch. 16", note: "Fishing, drinking, and the revelation of his name" },
        { book: "sut", locator: "Ch. 27", note: "Later appearance" }
      ]
    },
    {
      id: "leonard-sut", name: "Leonard", aliases: ["weird Leonard"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["the Huddle", "Knoxville", "the Tennessee River"],
      description: "An acquaintance who asks Suttree to help recover and dispose of his father’s hidden body. Leonard’s family has concealed the death in order to continue receiving benefit checks.",
      references: [
        { book: "sut", locator: "Chs. 16–17", note: "The problem of his father’s corpse" },
        { book: "sut", locator: "Ch. 28", note: "Later encounter" }
      ]
    },
    {
      id: "blind-richard", name: "Blind Richard", aliases: ["Richard"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville bars", "McAnally Flats"],
      description: "A blind man in Suttree’s barroom circle who appears in conversations and gatherings around McAnally Flats.",
      references: [
        { book: "sut", locator: "Ch. 4", note: "Early barroom appearance" },
        { book: "sut", locator: "Ch. 34", note: "Late appearance among Suttree’s friends" }
      ]
    },
    {
      id: "hoghead-henry", name: "Hoghead Henry", aliases: ["Hoghead", "James Henry"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["dies at twenty-one"], locations: ["Knoxville", "McAnally Flats", "the roadhouse"],
      description: "A young friend in the McAnally circle who appears in street conversations and bar fights. Suttree later learns that he has died at the age of twenty-one.",
      references: [
        { book: "sut", locator: "Ch. 4", note: "Conversation in Knoxville" },
        { book: "sut", locator: "Ch. 13", note: "The roadhouse brawl" },
        { book: "sut", locator: "Ch. 27", note: "News of his death" }
      ]
    },
    {
      id: "oceanfrog-frazer", name: "Oceanfrog Frazer", aliases: ["Oceanfrog"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Howard Clevenger’s store", "Ab Jones’s house", "McAnally Flats"],
      description: "A cardplayer and storyteller in the Black riverfront community, frequently encountered at Clevenger’s store and Ab Jones’s house.",
      references: [
        { book: "sut", locator: "Ch. 7", note: "At Clevenger’s and Ab’s" },
        { book: "sut", locator: "Ch. 11", note: "A later gathering" }
      ]
    },
    {
      id: "trippin-through-the-dew", name: "Trippin Through the Dew", aliases: ["Trippin"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["McAnally Flats", "Howard Clevenger’s store", "Ab Jones’s house"],
      description: "A member of the McAnally community who appears at Clevenger’s store, Ab Jones’s house, and other riverfront gatherings.",
      references: [
        { book: "sut", locator: "Ch. 7", note: "Introduced in the riverfront circle" },
        { book: "sut", locator: "Ch. 34", note: "Late appearance" }
      ]
    },
    {
      id: "cabbage-sut", name: "Cabbage", aliases: [], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville bars", "McAnally Flats", "the roadhouse"],
      description: "A member of Suttree’s drinking circle who joins the group’s overnight excursions and participates in the roadhouse fight.",
      references: [
        { book: "sut", locator: "Ch. 4", note: "In the Knoxville bar crowd" },
        { book: "sut", locator: "Ch. 13", note: "The roadhouse brawl" }
      ]
    },
    {
      id: "bearhunter-sut", name: "Bearhunter", aliases: [], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["McAnally Flats", "Knoxville bars"],
      description: "One of Suttree’s riverfront drinking companions, present during the opening visits to Knoxville taverns and mentioned again among his friends.",
      references: [
        { book: "sut", locator: "Ch. 1", note: "Opening night in Knoxville" },
        { book: "sut", locator: "Ch. 13", note: "Among the friends in Suttree’s vision" }
      ]
    },
    {
      id: "mother-she", name: "Mother She", aliases: [], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["McAnally Flats", "Knoxville"],
      description: "An elderly healer and diviner in the riverfront community whom Harrogate consults for a remedy.",
      references: [
        { book: "sut", locator: "Ch. 4", note: "Early mention in McAnally" },
        { book: "sut", locator: "Ch. 9", note: "Harrogate seeks her help" }
      ]
    },
    {
      id: "daddy-watson", name: "Daddy Watson", aliases: ["Watson"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["the Tennessee River", "McAnally Flats"],
      description: "An elderly man living by the river whose illness is described during one of Suttree’s visits.",
      references: [
        { book: "sut", locator: "Ch. 5", note: "Visit on the river" },
        { book: "sut", locator: "Ch. 25", note: "Later recollection" }
      ]
    },
    {
      id: "ragpicker-sut", name: "The ragpicker", aliases: ["the old ragpicker"], kind: "unnamed", prominence: "major",
      books: ["sut"], dates: ["early 1950s"], locations: ["beneath the Knoxville bridge", "the riverbank", "McAnally Flats"],
      description: "A scavenger who lives beneath a Knoxville bridge. He has several conversations with Suttree about death and later dies at his camp.",
      references: [
        { book: "sut", locator: "Ch. 1", note: "Introduced beneath the bridge" },
        { book: "sut", locator: "Ch. 6", note: "Harrogate at the ragpicker’s camp" },
        { book: "sut", locator: "Ch. 19", note: "Conversation about death" },
        { book: "sut", locator: "Ch. 29", note: "Final episode" }
      ]
    },
    {
      id: "goatman-sut", name: "The goatman", aliases: ["the goat preacher"], kind: "unnamed", prominence: "secondary",
      books: ["sut"], dates: ["spring in the early 1950s"], locations: ["Knoxville", "the field by the Tennessee River"],
      description: "An itinerant preacher who enters Knoxville with a train of goat-drawn carts, camps by the river, and debates scripture and salvation with Suttree.",
      references: [{ book: "sut", locator: "Ch. 14", note: "Arrival, camp, and conversations with Suttree" }]
    },
    {
      id: "howard-clevenger", name: "Howard Clevenger", aliases: ["Howard"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Howard Clevenger’s store", "Front Street", "McAnally Flats"],
      description: "The proprietor of a Front Street store where residents of McAnally gather, trade, and exchange news.",
      references: [
        { book: "sut", locator: "Ch. 7", note: "The store and its regulars" },
        { book: "sut", locator: "Ch. 11", note: "Another gathering at the store" }
      ]
    },
    {
      id: "mr-hatmaker", name: "Mr Hatmaker", aliases: ["Hatmaker"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "Hatmaker’s bar"],
      description: "A Knoxville tavern keeper whose establishment is regularly visited by Suttree and his friends.",
      references: [
        { book: "sut", locator: "Ch. 4", note: "At Hatmaker’s bar" },
        { book: "sut", locator: "Ch. 34", note: "Late return to the barroom circle" }
      ]
    },
    {
      id: "byrd-slusser", name: "Byrd Slusser", aliases: ["Slusser"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville workhouse"],
      description: "A workhouse inmate kept chained to a heavy pick. After a conflict with Callahan, he disappears from the workhouse narrative.",
      references: [{ book: "sut", locator: "Ch. 3", note: "Conflict in the workhouse" }]
    },
    {
      id: "rufus-wiley", name: "Rufus Wiley", aliases: ["Rufus"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "McAnally Flats"],
      description: "A riverfront acquaintance of Suttree and Harrogate who appears in connection with jobs and transactions around McAnally.",
      references: [
        { book: "sut", locator: "Ch. 9", note: "Encounter with Harrogate" },
        { book: "sut", locator: "Ch. 32", note: "Late appearance" }
      ]
    },
    {
      id: "willard-reese", name: "Willard Reese", aliases: ["Willard"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["the Reese camp", "the Tennessee River"],
      description: "Reese’s son and the principal boatman in the family’s mussel-fishing venture, working alongside Suttree while his father searches for pearls.",
      references: [{ book: "sut", locator: "Ch. 24", note: "The mussel-fishing expedition" }]
    },
    {
      id: "mrs-reese", name: "Mrs Reese", aliases: ["Reese’s wife"], kind: "unnamed", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["the Reese camp", "the Tennessee River"],
      description: "Reese’s wife, who manages the household and children at the family’s river camp during the pearl expedition.",
      references: [{ book: "sut", locator: "Ch. 24", note: "Life at the Reese camp" }]
    },
    {
      id: "suttree-wife", name: "Suttree’s wife", aliases: ["his estranged wife", "the boy’s mother"], kind: "unnamed", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "the family cemetery"],
      description: "Suttree’s estranged wife, encountered most directly after the death of their young son. Her family prevents Suttree from joining the mourners openly.",
      references: [{ book: "sut", locator: "Ch. 10", note: "Their son’s death and funeral" }]
    },
    {
      id: "suttree-son", name: "Suttree’s son", aliases: ["the boy", "the dead child"], kind: "unnamed", prominence: "major",
      books: ["sut"], dates: ["dies young in the early 1950s"], locations: ["Knoxville", "the family cemetery"],
      description: "Suttree’s young son, who lives with his mother and dies during the narrative. Suttree attends the burial without the family’s permission.",
      references: [{ book: "sut", locator: "Ch. 10", note: "News of the death, wake, and burial" }]
    },
    {
      id: "suttree-father", name: "Suttree’s father", aliases: ["Mr Suttree", "the elder Suttree"], kind: "unnamed", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Knoxville", "Suttree’s hospital room"],
      description: "Suttree’s father, a prosperous Knoxville man from whom he is estranged. He visits Suttree during his hospitalization.",
      references: [
        { book: "sut", locator: "Ch. 10", note: "Family conflict around the funeral" },
        { book: "sut", locator: "Ch. 34", note: "Visit during Suttree’s illness" }
      ]
    },
    {
      id: "aunt-martha-sut", name: "Aunt Martha", aliases: ["Martha"], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Suttree’s family home", "Knoxville"],
      description: "An older relative who receives Suttree during a visit to his family home and speaks with him about the family.",
      references: [{ book: "sut", locator: "Ch. 8", note: "Suttree’s visit with Aunt Martha" }]
    },
    {
      id: "doll-sut", name: "Doll", aliases: [], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["McAnally Flats", "Ab Jones’s house", "Knoxville"],
      description: "A woman in the Black riverfront community who appears in gatherings at Ab Jones’s house and elsewhere in McAnally.",
      references: [
        { book: "sut", locator: "Ch. 6", note: "Early appearance" },
        { book: "sut", locator: "Chs. 33–34", note: "Late appearance in McAnally" }
      ]
    },
    {
      id: "jabbo-sut", name: "Jabbo", aliases: [], kind: "person", prominence: "secondary",
      books: ["sut"], dates: ["early 1950s"], locations: ["Howard Clevenger’s store", "Ab Jones’s house", "McAnally Flats"],
      description: "A regular in the Black riverfront community who appears in conversations and card games at Clevenger’s store and Ab Jones’s house.",
      references: [
        { book: "sut", locator: "Ch. 7", note: "At Clevenger’s and Ab Jones’s" },
        { book: "sut", locator: "Ch. 11", note: "A later gathering" }
      ]
    },
    {
      id: "lester-ballard", name: "Lester Ballard", aliases: ["Ballard", "Lester"], kind: "person", prominence: "principal",
      books: ["cog"], dates: ["months before April 1965", "dies April 1965"],
      locations: ["Sevier County, Tennessee", "Frog Mountain", "Sevierville", "Lyons View", "Memphis"],
      description: "A resident of Sevier County whose property is sold by court order. He becomes increasingly isolated, commits several murders, conceals bodies in caves, and dies after being confined at a state hospital.",
      references: [
        { book: "cog", locator: "Part I, §1", note: "Auction of the Ballard property" },
        { book: "cog", locator: "Part II, §26", note: "The car on Frog Mountain" },
        { book: "cog", locator: "Part III, §§47–51", note: "Wounding, cave escape, surrender, and death" }
      ]
    },
    {
      id: "fate-turner", name: "Fate Turner", aliases: ["Sheriff Turner", "Fate", "the sheriff"], kind: "person", prominence: "major",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "Sevierville", "Frog Mountain"],
      description: "The county sheriff who arrests and questions Ballard and later participates in the search for him. He also recounts episodes from local history.",
      references: [
        { book: "cog", locator: "Part I, §15", note: "A deputy recalls riding with Fate" },
        { book: "cog", locator: "Part I, §18", note: "Arrest and interrogation of Ballard" },
        { book: "cog", locator: "Part III, §§42 and 45", note: "Investigation and flood journey" }
      ]
    },
    {
      id: "john-greer", name: "John Greer", aliases: ["Greer"], kind: "person", prominence: "major",
      books: ["cog"], dates: ["before April 1965"], locations: ["Grainger County", "the former Ballard property", "Sevier County"],
      description: "The purchaser and new occupant of Ballard’s former homeplace. Ballard spies on him, steals from him, and later attempts to kill him; Greer’s return fire costs Ballard an arm.",
      references: [
        { book: "cog", locator: "Part I, §2", note: "Identified as the buyer of the property" },
        { book: "cog", locator: "Part II, §§31 and 39–41", note: "Ballard watches and raids the homeplace" },
        { book: "cog", locator: "Part III, §47", note: "Ballard’s failed ambush" }
      ]
    },
    {
      id: "fred-kirby", name: "Fred Kirby", aliases: ["Kirby", "Fred"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "Kirby’s yard"],
      description: "A local acquaintance who trades in illicit whiskey and gives Ballard information, including news about the sheriff and the homeplace.",
      references: [
        { book: "cog", locator: "Part I, §3", note: "Ballard tries to buy whiskey" },
        { book: "cog", locator: "Part II, §33", note: "Conversation about Greer and the law" }
      ]
    },
    {
      id: "cb-auctioneer", name: "C B", aliases: ["the auctioneer"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Ballard property", "Sevier County"],
      description: "The auctioneer conducting the court-ordered sale of Ballard’s land. He refuses to be driven off when Ballard confronts the crowd with a rifle.",
      references: [{ book: "cog", locator: "Part I, §1", note: "The property auction and confrontation" }]
    },
    {
      id: "buster-cog", name: "Buster", aliases: [], kind: "person", prominence: "minor",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Ballard property"],
      description: "A man at the auction who strikes Ballard with an axe handle after the confrontation.",
      references: [{ book: "cog", locator: "Part I, §2", note: "A witness recalls the blow" }]
    },
    {
      id: "finney-boy", name: "The Finney boy", aliases: ["Finney"], kind: "person", prominence: "minor",
      books: ["cog"], dates: ["Ballard’s school years"], locations: ["Sevier County"],
      description: "A younger schoolboy whom Ballard punches after the boy refuses to retrieve a lost softball. The incident is recalled by a local narrator.",
      references: [{ book: "cog", locator: "Part I, §5", note: "A local narrator recalls the assault" }]
    },
    {
      id: "deputy-cotton", name: "Deputy Cotton", aliases: ["Cotton"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County sheriff’s office", "Sevierville"],
      description: "One of Fate Turner’s deputies, present during Ballard’s arrest, questioning, and the sheriff’s flooded tour of town.",
      references: [
        { book: "cog", locator: "Part I, §§17–18", note: "Arrest and complaint against Ballard" },
        { book: "cog", locator: "Part III, §45", note: "Rowing through flooded Sevierville" }
      ]
    },
    {
      id: "dumpkeeper", name: "The dumpkeeper", aliases: ["the old man at the dump"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Sevier County dump", "quarry woods"],
      description: "Keeper of the county dump, husband and father of nine daughters. He drinks with Ballard and receives him at the crowded family shack.",
      references: [
        { book: "cog", locator: "Part I, §9", note: "The dump household introduced" },
        { book: "cog", locator: "Part I, §13", note: "Conversation at the dump" },
        { book: "cog", locator: "Part II, §32", note: "Ballard visits after the fire" }
      ]
    },
    {
      id: "dumpkeepers-daughters", name: "The dumpkeeper’s daughters", aliases: ["Urethra", "Cerebella", "Hernia Sue", "the long-haired daughter"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Sevier County dump"],
      description: "Nine daughters living around the dump, several named from a discarded medical dictionary. Individual daughters recur in Ballard’s visits and one becomes his victim.",
      references: [
        { book: "cog", locator: "Part I, §9", note: "The daughters and their household" },
        { book: "cog", locator: "Part I, §24", note: "Ballard visits a daughter and her mother" },
        { book: "cog", locator: "Part II, §34", note: "Ballard attacks one of the daughters" }
      ]
    },
    {
      id: "mr-fox-cog", name: "Mr Fox", aliases: ["Fox", "the storekeeper"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Fox’s store", "Sevier County"],
      description: "A country storekeeper from whom Ballard buys food and receives local news.",
      references: [
        { book: "cog", locator: "Part II, §28", note: "Ballard buys supplies" },
        { book: "cog", locator: "Part II, §36", note: "A later visit to the store" }
      ]
    },
    {
      id: "blacksmith-cog", name: "The blacksmith", aliases: ["the smith"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County smithy"],
      description: "An unnamed craftsman who shows Ballard how to reforge and temper a damaged axehead.",
      references: [{ book: "cog", locator: "Part I, §23", note: "The axehead lesson" }]
    },
    {
      id: "john-cog", name: "John", aliases: ["Nigger John", "the Pine Bluff prisoner"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Pine Bluff, Arkansas", "Sevier County jail"],
      description: "A Black fugitive held in a cell opposite Ballard. He speaks with Ballard before the sheriff takes him away under sentence.",
      references: [{ book: "cog", locator: "Part I, §18", note: "Conversation across the jail corridor" }]
    },
    {
      id: "ballard-accuser", name: "Ballard’s accuser", aliases: ["the woman", "the young woman"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "sheriff’s office"],
      description: "A woman whom Ballard finds injured beside the road and carries toward town; she later accuses him of rape and fights him in the sheriff’s office.",
      references: [
        { book: "cog", locator: "Part I, §16", note: "Ballard finds her beside the road" },
        { book: "cog", locator: "Part I, §18", note: "Complaint and confrontation" }
      ]
    },
    {
      id: "frog-mountain-couple", name: "The couple in the car", aliases: ["the dead girl", "the dead man", "Ballard’s first corpse"], kind: "unnamed", prominence: "major",
      books: ["cog"], dates: ["December before April 1965"], locations: ["Frog Mountain turnaround", "Ballard’s cabin"],
      description: "A young couple found dead in an idling car. Ballard removes the woman’s body, keeps it at his cabin, and later moves it to a cave.",
      references: [
        { book: "cog", locator: "Part II, §26", note: "Discovery of the car and bodies" },
        { book: "cog", locator: "Part II, §§27–29", note: "The body concealed at the cabin" }
      ]
    },
    {
      id: "dump-daughter-child", name: "The idiot child", aliases: ["the child", "the cretin"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the dumpkeeper’s house"],
      description: "A disabled child in the dumpkeeper’s household who remains in the room when Ballard kills one of the daughters and sets the house afire.",
      references: [{ book: "cog", locator: "Part II, §34", note: "Witness to the attack and fire" }]
    },
    {
      id: "later-young-couple-cog", name: "The later young couple", aliases: ["the boy and girl in the truck"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["a mountain road in Sevier County"],
      description: "A courting pair surprised by Ballard in a parked truck. He kills the boy and attacks the girl, but the wounded boy escapes with the vehicle.",
      references: [{ book: "cog", locator: "Part III, §43", note: "Attack beside the mountain road" }]
    },
    {
      id: "tom-davis-cog", name: "Tom Davis", aliases: ["Sheriff Davis"], kind: "historical", prominence: "minor",
      books: ["cog"], dates: ["late nineteenth century", "sheriff by 1899"], locations: ["Sevier County", "Nashville", "Knoxville"],
      description: "A remembered Sevier County deputy and sheriff credited in Mr Wade’s flood-time story with breaking the White Caps and overseeing the 1899 hanging of two members.",
      references: [{ book: "cog", locator: "Part III, §45", note: "Mr Wade’s county history" }]
    },
    {
      id: "suzie-cog", name: "Suzie", aliases: ["Bill’s bird dog"], kind: "animal", prominence: "minor",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County hunting country"],
      description: "A bird dog mentioned in a local hunting anecdote about her supposed illness.",
      references: [{ book: "cog", locator: "Part I, §17", note: "The bird-dog story" }]
    },
    {
      id: "the-kid", name: "The kid", aliases: ["the man", "the child"], kind: "unnamed", prominence: "principal",
      books: ["bm"], dates: ["born 1833", "rides west in 1849", "Fort Griffin in 1878"],
      locations: ["Tennessee", "Nacogdoches", "San Antonio", "Chihuahua", "Sonora", "the Colorado River", "Fort Griffin"],
      description: "A nameless runaway from Tennessee who joins Captain White’s filibusters and later Glanton’s scalp-hunting company. He survives the destruction of both groups and reappears in 1878 as the man.",
      references: [
        { book: "bm", locator: "Chapter I", note: "Childhood, flight west, and Nacogdoches" },
        { book: "bm", locator: "Chapters III–VI", note: "Captain White’s expedition and entry into Glanton’s company" },
        { book: "bm", locator: "Chapters XX–XXIII", note: "Desert confrontation and return as the man" }
      ]
    },
    {
      id: "judge-holden", name: "Judge Holden", aliases: ["the judge", "Holden"], kind: "person", prominence: "principal",
      books: ["bm"], dates: ["1849–1850", "seen again in 1878"],
      locations: ["Nacogdoches", "Chihuahua", "Sonora", "Yuma ferry", "Fort Griffin"],
      description: "A large, hairless member of Glanton’s company whose learning encompasses languages, natural history, law, music, and military knowledge. He argues that conflict and domination are fundamental principles of human life.",
      references: [
        { book: "bm", locator: "Chapter I", note: "Accusation against Reverend Green" },
        { book: "bm", locator: "Chapters VII–XIV", note: "With Glanton’s gang and the ledger" },
        { book: "bm", locator: "Chapters XX–XXIII", note: "Pursuit of the kid and final appearance" }
      ]
    },
    {
      id: "john-joel-glanton", name: "John Joel Glanton", aliases: ["Glanton", "Captain Glanton"], kind: "historical", prominence: "principal",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "San Diego", "Yuma ferry"],
      description: "The historical Texan scalp hunter represented as captain of the company. He accepts contracts for Indigenous scalps, leads attacks in northern Mexico, and takes control of the Yuma ferry.",
      references: [
        { book: "bm", locator: "Chapter VI", note: "The contract with Governor Trías" },
        { book: "bm", locator: "Chapters VII–XVIII", note: "Command of the scalp-hunting company" },
        { book: "bm", locator: "Chapter XIX", note: "Rule and destruction of the ferry settlement" }
      ]
    },
    {
      id: "louis-toadvine", name: "Louis Toadvine", aliases: ["Toadvine"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Nacogdoches", "Chihuahua", "Sonora", "Los Angeles"],
      description: "A branded fugitive whom the kid meets in Nacogdoches. He later joins Glanton’s company and is hanged in Los Angeles.",
      references: [
        { book: "bm", locator: "Chapter I", note: "Fight, alliance, and hotel fire" },
        { book: "bm", locator: "Chapters V–XX", note: "Return in Chihuahua and service with Glanton" },
        { book: "bm", locator: "Chapter XXII", note: "Seen in Los Angeles" }
      ]
    },
    {
      id: "ben-tobin", name: "Ben Tobin", aliases: ["Tobin", "the expriest", "the priest"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Colorado River desert", "San Diego"],
      description: "An Irish former novice who rides with Glanton’s company. He recounts the judge’s arrival, warns the kid about him, and flees with the kid after the attack at the Yuma ferry.",
      references: [
        { book: "bm", locator: "Chapters VII–X", note: "Introduced and narrates the judge’s gunpowder feat" },
        { book: "bm", locator: "Chapters XX–XXII", note: "Flight from the judge and arrival in San Diego" }
      ]
    },
    {
      id: "david-brown-bm", name: "David Brown", aliases: ["Davy Brown", "Brown"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "San Diego", "Los Angeles"],
      description: "A member of Glanton’s company who takes part in its campaigns and disputes. He is jailed after a confrontation in San Diego and later executed in Los Angeles.",
      references: [
        { book: "bm", locator: "Chapters VII–XVII", note: "Campaigns with Glanton’s company" },
        { book: "bm", locator: "Chapter XIX", note: "San Diego arrest" },
        { book: "bm", locator: "Chapter XXII", note: "Fate in Los Angeles" }
      ]
    },
    {
      id: "black-jackson", name: "Black Jackson", aliases: ["John Jackson", "the black Jackson", "Blackie"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Yuma ferry"],
      description: "One of two members of the company named John Jackson. He kills the white Jackson after repeated racist provocation and remains with the group until the attack at the Yuma ferry.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "The two Jacksons introduced" },
        { book: "bm", locator: "Chapter VIII", note: "Killing of White Jackson" },
        { book: "bm", locator: "Chapter XIX", note: "At the Yuma ferry" }
      ]
    },
    {
      id: "white-jackson", name: "White Jackson", aliases: ["John Jackson", "the white Jackson"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1849"], locations: ["Chihuahua", "northern Mexico"],
      description: "The white member of the company who shares John Jackson’s name. Black Jackson kills him after a series of racist insults and threats.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Hostility between the two Jacksons" },
        { book: "bm", locator: "Chapter VIII", note: "Death in camp" }
      ]
    },
    {
      id: "sproule", name: "Sproule", aliases: [], kind: "person", prominence: "major",
      books: ["bm"], dates: ["dies 1849"], locations: ["Bolsón de Mapimí", "Chihuahua"],
      description: "A wounded survivor of the destruction of Captain White’s force. He crosses the desert with the kid, is bitten by a vampire bat, and dies near a carreta road.",
      references: [{ book: "bm", locator: "Chapter V", note: "Desert journey and death" }]
    },
    {
      id: "captain-white", name: "Captain White", aliases: ["White"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["dies 1849"], locations: ["San Antonio", "Laredito", "Chihuahua"],
      description: "The leader of an unauthorized American military expedition into Mexico. He recruits the kid in San Antonio, and Apache warriors later destroy the company.",
      references: [
        { book: "bm", locator: "Chapter III", note: "Recruitment and political program" },
        { book: "bm", locator: "Chapters IV–V", note: "March, massacre, and displayed head" }
      ]
    },
    {
      id: "bathcat", name: "Bathcat", aliases: ["the Vandiemenlander"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1849"], locations: ["Wales", "Van Diemen’s Land", "Chihuahua", "Sonora"],
      description: "A Welsh-born former convict from Van Diemen’s Land who befriends Toadvine and rides with Glanton’s company.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Introduced beside Toadvine" },
        { book: "bm", locator: "Chapters VIII–XIII", note: "Campaign and death" }
      ]
    },
    {
      id: "sam-tate-bm", name: "Sam Tate", aliases: ["Tate"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Kentucky", "Chihuahua", "Sonora", "Colorado River country"],
      description: "A Kentuckian and former McCulloch’s Ranger in Glanton’s company. He is paired with the kid during the wounded men’s lottery and later disappears during a crossing.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Named among the company" },
        { book: "bm", locator: "Chapter XV", note: "Lottery and flight from Elías" }
      ]
    },
    {
      id: "webster-bm", name: "Webster", aliases: ["the Tennessean", "Long Webster"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849–1850"], locations: ["Tennessee", "Chihuahua", "Sonora", "San Diego"],
      description: "A Tennessean in Glanton’s company who questions the judge about his sketches and later rides to San Diego for supplies.",
      references: [
        { book: "bm", locator: "Chapter XI", note: "Questions the judge’s ledger" },
        { book: "bm", locator: "Chapter XIX", note: "Supply ride to San Diego" }
      ]
    },
    {
      id: "dick-shelby", name: "Dick Shelby", aliases: ["Shelby"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Sonora"],
      description: "A wounded member of Glanton’s company left behind during General Elías’s pursuit. The kid refuses the order to kill him.",
      references: [{ book: "bm", locator: "Chapter XV", note: "The wounded men’s lottery" }]
    },
    {
      id: "doc-irving", name: "Doc Irving", aliases: ["Irving"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Yuma ferry"],
      description: "The doctor attached to Glanton’s company. He is killed during the attack at the Yuma ferry.",
      references: [
        { book: "bm", locator: "Chapter IX", note: "Treats—or declines to treat—the wounded" },
        { book: "bm", locator: "Chapter XIX", note: "Death at the ferry" }
      ]
    },
    {
      id: "delaware-guides", name: "The Delaware guides", aliases: ["the Delawares"], kind: "unnamed", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Arizona", "Colorado River"],
      description: "A group of Delaware scouts who guide Glanton’s company and track its enemies. Several are killed during the campaigns.",
      references: [
        { book: "bm", locator: "Chapters VII–XII", note: "Scouting for Glanton’s company" },
        { book: "bm", locator: "Chapters XV–XVII", note: "Retreat and losses" }
      ]
    },
    {
      id: "john-mcgill", name: "John McGill", aliases: ["Juan Miguel", "McGill"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1850"], locations: ["Mexico", "Yuma ferry"],
      description: "A Mexican member of Glanton’s multinational company whose name has been anglicized. He is killed during the Yuma assault on the ferry camp.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Named among the company" },
        { book: "bm", locator: "Chapter XIX", note: "Death at the ferry" }
      ]
    },
    {
      id: "james-robert-bell", name: "James Robert Bell", aliases: ["the idiot", "the fool"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1850"], locations: ["Tucson", "Yuma crossing", "Arizona desert"],
      description: "Cloyce Bell’s disabled younger brother, exhibited for money and later taken into the judge’s entourage.",
      references: [
        { book: "bm", locator: "Chapter XVI", note: "The Bell brothers introduced" },
        { book: "bm", locator: "Chapter XVIII", note: "Named and cared for by Sarah Borginnis" },
        { book: "bm", locator: "Chapters XXI–XXII", note: "Travels with the judge" }
      ]
    },
    {
      id: "cloyce-bell", name: "Cloyce Bell", aliases: ["Mr Bell"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1850"], locations: ["Tucson", "Yuma crossing", "Arizona desert"],
      description: "James Robert’s elder brother and keeper, who exhibits him as a curiosity until Sarah Borginnis intervenes.",
      references: [
        { book: "bm", locator: "Chapter XVI", note: "Travels with his brother" },
        { book: "bm", locator: "Chapter XVIII", note: "Confrontation with Sarah Borginnis" }
      ]
    },
    {
      id: "sarah-borginnis", name: "Sarah Borginnis", aliases: ["Mrs Borginnis"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1850"], locations: ["Yuma crossing", "Colorado River"],
      description: "A woman in San Diego who washes, clothes, and feeds James Robert Bell and rebukes Cloyce for exhibiting him for money.",
      references: [{ book: "bm", locator: "Chapter XVIII", note: "Care of James Robert Bell" }]
    },
    {
      id: "speyer-bm", name: "Speyer", aliases: ["the Prussian arms dealer"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Chihuahua City"],
      description: "A Prussian Jewish merchant who sells Glanton’s men a case of Colt revolvers and negotiates the price with Glanton.",
      references: [{ book: "bm", locator: "Chapter VII", note: "Sale of the revolvers" }]
    },
    {
      id: "reverend-green", name: "Reverend Green", aliases: ["the Reverend"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Nacogdoches, Texas"],
      description: "A traveling revival preacher. Judge Holden disrupts his meeting by falsely accusing him of crimes before the assembled crowd.",
      references: [{ book: "bm", locator: "Chapter I", note: "The judge’s false accusation" }]
    },
    {
      id: "mennonite-bm", name: "The Mennonite", aliases: ["the old Mennonite"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Laredito"],
      description: "An older man who warns Captain White’s recruits about the probable consequences of their expedition into Mexico.",
      references: [{ book: "bm", locator: "Chapter III", note: "Warning in the cantina" }]
    },
    {
      id: "hermit-bm", name: "The hermit", aliases: ["the old hermit"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["East Texas"],
      description: "A former slaver living alone who shelters the kid for a night and speaks about human nature and racial violence.",
      references: [{ book: "bm", locator: "Chapter II", note: "Night in the hermit’s hut" }]
    },
    {
      id: "angel-trias", name: "Ángel Trías", aliases: ["Governor Trías", "Trias"], kind: "historical", prominence: "secondary",
      books: ["bm"], dates: ["governor of Chihuahua in 1849"], locations: ["Chihuahua City"],
      description: "The governor of Chihuahua who contracts Glanton’s company for Apache scalps and pays the company on its return to the city.",
      references: [
        { book: "bm", locator: "Chapter VI", note: "Glanton’s contract described" },
        { book: "bm", locator: "Chapter XIII", note: "Reception and banquet in Chihuahua" }
      ]
    },
    {
      id: "general-elias", name: "General Elías", aliases: ["Elias"], kind: "historical", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Sonora", "Baviácora", "Nacozari"],
      description: "The Sonoran commander whose cavalry pursues Glanton’s gang after its indiscriminate killings and scalp frauds.",
      references: [{ book: "bm", locator: "Chapter XV", note: "Pursuit across Sonora" }]
    },
    {
      id: "owens-bm", name: "Owens", aliases: ["Mr Owens"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1850"], locations: ["San Diego"],
      description: "A San Diego saloon proprietor who objects to Glanton’s gang occupying his establishment and is shot by Glanton.",
      references: [{ book: "bm", locator: "Chapter XVI", note: "Confrontation in the saloon" }]
    },
    {
      id: "elrod-bm", name: "Elrod", aliases: ["the bonepicker"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1878"], locations: ["north Texas plains"],
      description: "A teenage bonepicker who challenges the man beside a prairie fire. The man shoots and kills him.",
      references: [{ book: "bm", locator: "Chapter XXIII", note: "Night with the bonepickers" }]
    },
    {
      id: "juggler-couple-bm", name: "The juggler and fortune-teller", aliases: ["the juggler", "the old woman", "the soothsayer"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Janos", "Nacori"],
      description: "Itinerant performers who entertain Glanton’s company with juggling and fortune-telling. Their card readings refer to several members of the group.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Performance and readings at Janos" },
        { book: "bm", locator: "Chapter XIII", note: "A later encounter" }
      ]
    },
    {
      id: "sergeant-aguilar", name: "Sergeant Aguilar", aliases: ["Aguilar"], kind: "person", prominence: "minor",
      books: ["bm"], dates: ["1849"], locations: ["Janos"],
      description: "A Mexican sergeant who confronts the armed Americans at Janos. The judge resolves the encounter through a formal exchange with him.",
      references: [{ book: "bm", locator: "Chapter VII", note: "Encounter at Janos" }]
    },
    {
      id: "lieutenant-couts", name: "Lieutenant Cave J. Couts", aliases: ["Lieutenant Couts", "Couts"], kind: "historical", prominence: "minor",
      books: ["bm"], dates: ["1850"], locations: ["Tucson"],
      description: "The U.S. Army lieutenant commanding the garrison at Tucson when Glanton’s company arrives and Apache visitors demand whiskey.",
      references: [{ book: "bm", locator: "Chapter XVI", note: "Encounter at the Tucson garrison" }]
    },
    {
      id: "mangas-colorado", name: "Mangas Colorado", aliases: ["Mangas"], kind: "historical", prominence: "minor",
      books: ["bm"], dates: ["1850"], locations: ["Tucson", "Santa Cruz valley"],
      description: "An Apache leader who meets Glanton after one of his riders collides with the company and later asks the Americans for whiskey near Tucson.",
      references: [{ book: "bm", locator: "Chapter XVI", note: "Parley outside Tucson" }]
    },
    {
      id: "major-graham-bm", name: "Major Graham", aliases: ["Graham"], kind: "historical", prominence: "minor",
      books: ["bm"], dates: ["1850"], locations: ["Tucson", "California route", "Colorado River"],
      description: "A U.S. officer whose command is recalled in connection with Lieutenant Couts’s coastal journey and the freight wagons later used at the Colorado River ferry.",
      references: [
        { book: "bm", locator: "Chapter XVI", note: "Mentioned by Lieutenant Couts" },
        { book: "bm", locator: "Chapter XIX", note: "His command’s wagons at the ferry" }
      ]
    },
    {
      id: "john-grady-cole", name: "John Grady Cole", aliases: ["John Grady", "John Cole"], kind: "person", prominence: "principal",
      books: ["atph", "cities"], dates: ["born c. 1933", "1949–1952"],
      locations: ["San Angelo, Texas", "La Purísima, Coahuila", "Saltillo", "Orogrande, New Mexico", "Ciudad Juárez"],
      description: "A Texas horseman and the principal character of All the Pretty Horses. He later works at Mac McGovern’s Cross Fours ranch and attempts to marry Magdalena in Cities of the Plain.",
      references: [
        { book: "atph", locator: "Part I", note: "Opening at the Grady ranch" },
        { book: "atph", locator: "Part II", note: "La Purísima" },
        { book: "cities", locator: "Part I, §1", note: "At the Cross Fours and in Juárez" },
        { book: "cities", locator: "Part IV, §1", note: "Final confrontation" }
      ]
    },
    {
      id: "lacey-rawlins", name: "Lacey Rawlins", aliases: ["Rawlins"], kind: "person", prominence: "principal",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["San Angelo, Texas", "Coahuila", "Encantada", "Saltillo"],
      description: "John Grady’s friend and traveling companion in Mexico. He returns to Texas after their imprisonment in Saltillo.",
      references: [
        { book: "atph", locator: "Part I", note: "Departure from Texas" },
        { book: "atph", locator: "Part III", note: "Arrest and imprisonment" }
      ]
    },
    {
      id: "jimmy-blevins", name: "Jimmy Blevins", aliases: ["Blevins"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1949"], locations: ["Texas–Mexico borderlands", "Encantada"],
      description: "A young runaway who joins John Grady and Rawlins. His possession of a stolen horse and pistol leads to the arrest of all three travelers in Mexico.",
      references: [
        { book: "atph", locator: "Part I", note: "Joins the riders and loses his horse" },
        { book: "atph", locator: "Part III", note: "Held in Encantada" }
      ]
    },
    {
      id: "alejandra-rocha", name: "Alejandra Rocha", aliases: ["Alejandra"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima, Coahuila", "Mexico City", "Zacatecas"],
      description: "Don Héctor’s daughter, Alfonsa’s grandniece and goddaughter, and John Grady’s lover.",
      references: [
        { book: "atph", locator: "Part II", note: "Named at La Purísima" },
        { book: "atph", locator: "Part IV", note: "Meeting in Zacatecas" }
      ]
    },
    {
      id: "alfonsa", name: "Alfonsa", aliases: ["Dueña Alfonsa", "Señorita Alfonsa"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["Mexican Revolution recalled", "c. 1950"], locations: ["La Purísima", "Mexico City", "Europe", "London"],
      description: "Alejandra’s grandaunt and godmother. She recounts her experience of the Mexican Revolution and intervenes to end Alejandra’s relationship with John Grady.",
      references: [
        { book: "atph", locator: "Part II", note: "Chess and first conversation" },
        { book: "atph", locator: "Part IV", note: "Family history and decision" }
      ]
    },
    {
      id: "don-hector", name: "Don Héctor Rocha y Villareal", aliases: ["Don Héctor", "the hacendado"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima, Coahuila", "Mexico City"],
      description: "The owner of La Purísima, Alejandra’s father, and a horse breeder who employs John Grady to work with the ranch’s stallions.",
      references: [
        { book: "atph", locator: "Part II", note: "La Purísima introduced" },
        { book: "atph", locator: "Part II", note: "John Grady works with the stallion" }
      ]
    },
    {
      id: "emilio-perez", name: "Emilio Pérez", aliases: ["Pérez"], kind: "person", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["Saltillo prison"],
      description: "A prisoner who controls access to protection within the Saltillo prison and explains its arrangements to John Grady.",
      references: [{ book: "atph", locator: "Part III", note: "Meeting in Saltillo prison" }]
    },
    {
      id: "encantada-captain", name: "The captain", aliases: ["Mexican captain", "the madrina"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["c. 1950"], locations: ["Encantada"],
      description: "The local police captain who interrogates John Grady and Rawlins and orders Blevins’s execution.",
      references: [{ book: "atph", locator: "Part III", note: "Interrogations and transport" }]
    },
    {
      id: "john-gradys-father", name: "John Grady’s father", aliases: ["Mr Cole", "John Grady’s father"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["Second World War", "dies c. 1950"], locations: ["San Angelo", "San Antonio", "San Diego"],
      description: "A Second World War veteran separated from John Grady’s mother and in poor health. His knife later passes to his son.",
      references: [{ book: "atph", locator: "Part I", note: "Conversations in San Angelo" }]
    },
    {
      id: "john-gradys-mother", name: "John Grady’s mother", aliases: ["Mrs Cole", "John Grady’s mother"], kind: "unnamed", prominence: "major",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo", "San Antonio"],
      description: "An actress who inherits the family ranch and decides to sell it. John Grady leaves Texas after failing to prevent the sale.",
      references: [{ book: "atph", locator: "Part I", note: "Ranch inheritance and sale" }]
    },
    {
      id: "franklin", name: "Franklin", aliases: ["Mr Franklin"], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo"],
      description: "The family lawyer whom John Grady consults in an unsuccessful attempt to prevent the ranch’s sale.",
      references: [{ book: "atph", locator: "Part I", note: "Legal consultation" }]
    },
    {
      id: "abuela", name: "Abuela", aliases: ["Luisa’s mother"], kind: "unnamed", prominence: "secondary",
      books: ["atph"], dates: ["family service for fifty years", "dies c. 1950"], locations: ["Grady ranch", "Knickerbocker, Texas"],
      description: "The elderly woman who cared for generations of the Grady family and whom John Grady calls his grandmother.",
      references: [
        { book: "atph", locator: "Part I", note: "Family history" },
        { book: "atph", locator: "Part IV", note: "Death and burial" }
      ]
    },
    {
      id: "luisa", name: "Luisa", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["Grady ranch", "San Angelo"],
      description: "A longtime member of the Grady household and Abuela’s daughter.",
      references: [{ book: "atph", locator: "Part I", note: "At the Grady ranch" }]
    },
    {
      id: "arturo", name: "Arturo", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1949–1950"], locations: ["Grady ranch", "San Angelo"],
      description: "A worker at the Grady ranch and member of its dwindling household.",
      references: [{ book: "atph", locator: "Part I", note: "At the Grady ranch" }]
    },
    {
      id: "antonio-atph", name: "Antonio", aliases: ["Armando’s brother"], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima", "Kentucky", "Tennessee", "Texas"],
      description: "Armando’s brother, remembered for transporting Don Héctor’s American stallion from Kentucky to Mexico.",
      references: [{ book: "atph", locator: "Part II", note: "Journey with the stallion" }]
    },
    {
      id: "armando", name: "Armando", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A senior horseman at La Purísima who reports John Grady’s abilities to Don Héctor.",
      references: [{ book: "atph", locator: "Part II", note: "Horse work at La Purísima" }]
    },
    {
      id: "maria-atph", name: "María", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A member of the household staff at La Purísima, frequently associated with the kitchen and meals.",
      references: [{ book: "atph", locator: "Part II", note: "Household scenes" }]
    },
    {
      id: "carlos-atph", name: "Carlos", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "A servant in Don Héctor and Alfonsa’s household.",
      references: [{ book: "atph", locator: "Part II", note: "Household and billiard-room scenes" }]
    },
    {
      id: "roberto-atph", name: "Roberto", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima", "local dance"],
      description: "A young ranch worker who attends the local dance with John Grady and Rawlins.",
      references: [{ book: "atph", locator: "Part II", note: "Dance" }]
    },
    {
      id: "esteban-atph", name: "Estéban", aliases: [], kind: "person", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["La Purísima"],
      description: "An elderly stable worker at La Purísima.",
      references: [{ book: "atph", locator: "Part II", note: "Stable scenes" }]
    },
    {
      id: "mary-catherine", name: "Mary Catherine", aliases: [], kind: "person", prominence: "minor",
      books: ["atph"], dates: ["c. 1949"], locations: ["San Angelo"],
      description: "John Grady’s former girlfriend, encountered shortly before he leaves Texas.",
      references: [{ book: "atph", locator: "Part I", note: "Brief conversation" }]
    },
    {
      id: "ozona-judge", name: "The Ozona judge", aliases: ["the judge"], kind: "unnamed", prominence: "secondary",
      books: ["atph"], dates: ["c. 1950"], locations: ["Ozona, Texas"],
      description: "The judge who hears John Grady’s horse-ownership case and later receives his confession and doubts.",
      references: [{ book: "atph", locator: "Part IV", note: "Hearing and evening conversation" }]
    },
    {
      id: "gustavo-madero", name: "Gustavo A. Madero", aliases: ["Gustavo"], kind: "historical", prominence: "secondary",
      books: ["atph"], dates: ["Mexican Revolution", "died 1913"], locations: ["Mexico", "Europe"],
      description: "Historical revolutionary and Alfonsa’s youthful love, recalled in her account of the Madero family and the revolution.",
      references: [{ book: "atph", locator: "Part IV", note: "Alfonsa’s recollection" }]
    },
    {
      id: "francisco-madero", name: "Francisco I. Madero", aliases: ["Francisco Madero", "Francisco"], kind: "historical", prominence: "secondary",
      books: ["atph"], dates: ["Mexican Revolution", "president 1911–1913"], locations: ["Coahuila", "Mexico City"],
      description: "The historical president and revolutionary, remembered by Alfonsa as a friend of her family and as Gustavo Madero’s brother.",
      references: [{ book: "atph", locator: "Part IV", note: "Alfonsa’s recollection" }]
    },

    {
      id: "billy-parham", name: "Billy Parham", aliases: ["Billy", "Mr Parham"], kind: "person", prominence: "principal",
      books: ["crossing", "cities"], dates: ["born c. 1925", "late 1930s–c. 2001"],
      locations: ["Hidalgo County, New Mexico", "Chihuahua", "Sonora", "Orogrande", "El Paso", "De Baca County"],
      description: "The principal character of The Crossing and an older coworker of John Grady in Cities of the Plain. The epilogue follows him into old age around the beginning of the twenty-first century.",
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
      description: "Billy’s younger brother, who accompanies him into Mexico after their parents’ deaths. Later accounts of his life and death circulate in northern Mexico.",
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
      description: "A pregnant Mexican wolf trapped by Billy, who attempts to return her across the border rather than kill her.",
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
      description: "A trapper whose cabin, equipment, and methods Billy studies while pursuing the wolf, although Echols does not appear directly.",
      references: [{ book: "crossing", locator: "Part I, §1", note: "Cabin and trapping materials" }]
    },
    {
      id: "the-mormon", name: "The Mormon", aliases: ["the former Mormon"], kind: "unnamed", prominence: "secondary",
      books: ["crossing"], dates: ["late 1930s or early 1940s"], locations: ["northern Mexico"],
      description: "A former Mormon who gives Billy food and discusses God, suffering, and witness with him.",
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
      description: "A former revolutionary who recounts his blinding and his experiences of imprisonment and political violence to Billy and Boyd.",
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
      description: "A labor organizer killed with Crecencio Macias and Manuel Jiménez by the Guardias Blancas during conflict on the Babícora estate.",
      references: [{ book: "crossing", locator: "Part IV, §3", note: "Quijada’s account" }]
    },
    {
      id: "william-randolph-hearst", name: "William Randolph Hearst", aliases: ["Mr Hearst", "Señor Hearst"], kind: "historical", prominence: "secondary",
      books: ["crossing"], dates: ["early 1940s"], locations: ["Babícora", "Chihuahua"],
      description: "The historical American owner of the Babícora estate, mentioned in accounts of its conflict with local campesinos.",
      references: [
        { book: "crossing", locator: "Part II, §2", note: "Babícora identified" },
        { book: "crossing", locator: "Part IV, §3", note: "Quijada discusses the latifundio" }
      ]
    },
    {
      id: "alfonso-crossing", name: "Alfonso", aliases: [], kind: "person", prominence: "minor",
      books: ["crossing"], dates: ["1940s"], locations: ["Mexico"],
      description: "A man whom Billy meets while drinking in a bar during his later travels in Mexico.",
      references: [{ book: "crossing", locator: "Part IV, §2", note: "Barroom encounter" }]
    },
    {
      id: "gypsy-chief", name: "The gypsy", aliases: ["the gypsy chief", "the drover"], kind: "unnamed", prominence: "major",
      books: ["crossing"], dates: ["1945"], locations: ["Mexican borderlands", "river woods"],
      description: "The leader of a group of Roma drovers who speaks with Billy about objects, memory, and representation.",
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
      description: "An unnamed young woman who travels with Boyd during his later life in Mexico and appears in accounts given to Billy.",
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
      description: "The proprietor of the White Lake brothel, who controls Magdalena and opposes John Grady’s plan to take her to the United States.",
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
      description: "A cowboy at the Cross Fours who takes responsibility for various ranch tasks and decisions.",
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
      description: "One of the Cross Fours cowboys, appearing in the group’s stories, conversations, and ranch work.",
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
      description: "An older hunter who recalls the 1913 fighting in Juárez during a hunting trip with the ranch hands.",
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
      description: "The cook at the Cross Fours ranch, responsible for meals and household work.",
      references: [{ book: "cities", locator: "Part I, §§1–3", note: "Kitchen and household scenes" }]
    },
    {
      id: "mr-johnson", name: "Mr Johnson", aliases: ["Johnson", "old man Johnson"], kind: "person", prominence: "major",
      books: ["cities"], dates: ["born in the nineteenth century", "1952"], locations: ["El Paso", "Las Cruces", "Cross Fours ranch"],
      description: "An elderly cowboy and Mac’s father-in-law who recounts episodes from his earlier life in the cattle business.",
      references: [
        { book: "cities", locator: "Part I, §1", note: "At the Cross Fours" },
        { book: "cities", locator: "Part II, §2", note: "Night conversation" }
      ]
    },
    {
      id: "margaret-mcgovern", name: "Margaret Johnson McGovern", aliases: ["Margaret"], kind: "person", prominence: "secondary",
      books: ["cities"], dates: ["died before 1952"], locations: ["Las Cruces", "Cross Fours ranch"],
      description: "Mr Johnson’s daughter and Mac’s late wife, remembered for her work with horses.",
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
      description: "A horseman at the Cross Fours who helps handle a difficult stallion.",
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
      description: "A blind musician at the White Lake who speaks with John Grady about Magdalena, Eduardo, beauty, and fate.",
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
      description: "An unnamed man who tells the elderly Billy a nested dream and discusses possible interpretations of it in the epilogue.",
      references: [{ book: "cities", locator: "Part IV, §3", note: "Conversation beneath the overpass" }]
    },
    {
      id: "billy-sanchez", name: "Billy Sánchez", aliases: [], kind: "person", prominence: "minor",
      books: ["cities"], dates: ["before 1952"], locations: ["Mexico", "New Mexico"],
      description: "A horse trainer mentioned by Joaquín as an example of a person whom horses followed without coercion.",
      references: [{ book: "cities", locator: "Part I, §1", note: "Joaquín’s observation" }]
    }
  ]
};
