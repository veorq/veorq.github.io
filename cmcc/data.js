window.CONCORDANCE_DATA = {
  meta: {
    title: "The Cormac McCarthy Concordance",
    subtitle: "Persons, places, dates, and crossings",
    updated: "29 August 2026",
    notice: "Contains plot details and endings.",
    sourceNote: "References were checked against the supplied EPUB editions. All the Pretty Horses and Child of God preserve print-page anchors. Blood Meridian is cited by chapter; The Crossing and Cities of the Plain are cited by Part and EPUB section because those files have no stable page map."
  },

  books: [
    { id: "oph", title: "The Orchard Keeper", year: 1965, indexed: false },
    { id: "od", title: "Outer Dark", year: 1968, indexed: false },
    {
      id: "cog", title: "Child of God", year: 1973, indexed: true,
      period: "months before April 1965", sections: "Parts I–III; 52 short sections", referenceSystem: "Part, section, and print page",
      edition: "Knopf Doubleday EPUB, ISBN 978-0-307-76248-1"
    },
    { id: "sut", title: "Suttree", year: 1979, indexed: false },
    {
      id: "bm", title: "Blood Meridian", year: 1985, indexed: true,
      period: "1849–1850; final chapter in 1878", sections: "Chapters I–XXIII and epilogue", referenceSystem: "Chapter",
      edition: "Picador EPUB, ISBN 978-1-4472-8946-3; supplied file has no print-page map"
    },
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
      id: "lester-ballard", name: "Lester Ballard", aliases: ["Ballard", "Lester"], kind: "person", prominence: "principal",
      books: ["cog"], dates: ["months before April 1965", "dies April 1965"],
      locations: ["Sevier County, Tennessee", "Frog Mountain", "Sevierville", "Lyons View", "Memphis"],
      description: "A dispossessed Sevier County loner whose expulsion from his land and community accelerates into murder, necrophilia, cave-dwelling, capture, and institutional death.",
      references: [
        { book: "cog", locator: "Part I, §1, pp. 3–8", note: "Auction of the Ballard property" },
        { book: "cog", locator: "Part II, §26, pp. 84–92", note: "The car on Frog Mountain" },
        { book: "cog", locator: "Part III, §§47–51, pp. 172–194", note: "Wounding, cave escape, surrender, and death" }
      ]
    },
    {
      id: "fate-turner", name: "Fate Turner", aliases: ["Sheriff Turner", "Fate", "the sheriff"], kind: "person", prominence: "major",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "Sevierville", "Frog Mountain"],
      description: "The plainspoken county sheriff who repeatedly arrests, questions, releases, and finally hunts Ballard. He is both an agent of the law and a local storyteller.",
      references: [
        { book: "cog", locator: "Part I, §15, pp. 44–45", note: "A deputy recalls riding with Fate" },
        { book: "cog", locator: "Part I, §18, pp. 50–56", note: "Arrest and interrogation of Ballard" },
        { book: "cog", locator: "Part III, §§42 and 45, pp. 145–168", note: "Investigation and flood journey" }
      ]
    },
    {
      id: "john-greer", name: "John Greer", aliases: ["Greer"], kind: "person", prominence: "major",
      books: ["cog"], dates: ["before April 1965"], locations: ["Grainger County", "the former Ballard property", "Sevier County"],
      description: "The purchaser and new occupant of Ballard’s former homeplace. Ballard spies on him, steals from him, and later attempts to kill him; Greer’s return fire costs Ballard an arm.",
      references: [
        { book: "cog", locator: "Part I, §2, p. 9", note: "Identified as the buyer of the property" },
        { book: "cog", locator: "Part II, §§31 and 39–41, pp. 109–141", note: "Ballard watches and raids the homeplace" },
        { book: "cog", locator: "Part III, §47, pp. 172–173", note: "Ballard’s failed ambush" }
      ]
    },
    {
      id: "fred-kirby", name: "Fred Kirby", aliases: ["Kirby", "Fred"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "Kirby’s yard"],
      description: "A local acquaintance who trades in illicit whiskey and gives Ballard information, including news about the sheriff and the homeplace.",
      references: [
        { book: "cog", locator: "Part I, §3, pp. 10–12", note: "Ballard tries to buy whiskey" },
        { book: "cog", locator: "Part II, §33, pp. 113–114", note: "Conversation about Greer and the law" }
      ]
    },
    {
      id: "cb-auctioneer", name: "C B", aliases: ["the auctioneer"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Ballard property", "Sevier County"],
      description: "The auctioneer conducting the court-ordered sale of Ballard’s land. He refuses to be driven off when Ballard confronts the crowd with a rifle.",
      references: [{ book: "cog", locator: "Part I, §1, pp. 5–8", note: "The property auction and confrontation" }]
    },
    {
      id: "buster-cog", name: "Buster", aliases: [], kind: "person", prominence: "minor",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Ballard property"],
      description: "A man at the auction who strikes Ballard with an axe handle after the confrontation.",
      references: [{ book: "cog", locator: "Part I, §2, p. 9", note: "A witness recalls the blow" }]
    },
    {
      id: "finney-boy", name: "The Finney boy", aliases: ["Finney"], kind: "person", prominence: "minor",
      books: ["cog"], dates: ["Ballard’s school years"], locations: ["Sevier County"],
      description: "A younger schoolboy whom Ballard punches for refusing to retrieve a lost softball, in an early community memory of Ballard’s violence.",
      references: [{ book: "cog", locator: "Part I, §5, pp. 17–18", note: "A local narrator recalls the assault" }]
    },
    {
      id: "deputy-cotton", name: "Deputy Cotton", aliases: ["Cotton"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County sheriff’s office", "Sevierville"],
      description: "One of Fate Turner’s deputies, present during Ballard’s arrest, questioning, and the sheriff’s flooded tour of town.",
      references: [
        { book: "cog", locator: "Part I, §§17–18, pp. 48–52", note: "Arrest and complaint against Ballard" },
        { book: "cog", locator: "Part III, §45, pp. 160–168", note: "Rowing through flooded Sevierville" }
      ]
    },
    {
      id: "dumpkeeper", name: "The dumpkeeper", aliases: ["the old man at the dump"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Sevier County dump", "quarry woods"],
      description: "Keeper of the county dump, husband and father of nine daughters. He drinks with Ballard and receives him at the crowded family shack.",
      references: [
        { book: "cog", locator: "Part I, §9, pp. 25–30", note: "The dump household introduced" },
        { book: "cog", locator: "Part I, §13, pp. 37–39", note: "Conversation at the dump" },
        { book: "cog", locator: "Part II, §32, pp. 110–112", note: "Ballard visits after the fire" }
      ]
    },
    {
      id: "dumpkeepers-daughters", name: "The dumpkeeper’s daughters", aliases: ["Urethra", "Cerebella", "Hernia Sue", "the long-haired daughter"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the Sevier County dump"],
      description: "Nine daughters living around the dump, several named from a discarded medical dictionary. Individual daughters recur in Ballard’s visits and one becomes his victim.",
      references: [
        { book: "cog", locator: "Part I, §9, pp. 26–30", note: "The daughters and their household" },
        { book: "cog", locator: "Part I, §24, pp. 75–79", note: "Ballard visits a daughter and her mother" },
        { book: "cog", locator: "Part II, §34, pp. 115–120", note: "Ballard attacks one of the daughters" }
      ]
    },
    {
      id: "mr-fox-cog", name: "Mr Fox", aliases: ["Fox", "the storekeeper"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Fox’s store", "Sevier County"],
      description: "A country storekeeper who sells Ballard food and hears local news, providing one of Ballard’s few recurring points of contact with ordinary commerce.",
      references: [
        { book: "cog", locator: "Part II, §28, pp. 96–100", note: "Ballard buys supplies" },
        { book: "cog", locator: "Part II, §36, pp. 124–126", note: "A later visit to the store" }
      ]
    },
    {
      id: "blacksmith-cog", name: "The blacksmith", aliases: ["the smith"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County smithy"],
      description: "An unnamed craftsman who patiently shows Ballard how to reforge and temper a damaged axehead.",
      references: [{ book: "cog", locator: "Part I, §23, pp. 70–74", note: "The axehead lesson" }]
    },
    {
      id: "john-cog", name: "John", aliases: ["Nigger John", "the Pine Bluff prisoner"], kind: "person", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Pine Bluff, Arkansas", "Sevier County jail"],
      description: "A Black fugitive held opposite Ballard in jail. His sardonic conversations with Ballard end when the sheriff takes him away under sentence.",
      references: [{ book: "cog", locator: "Part I, §18, pp. 53–54", note: "Conversation across the jail corridor" }]
    },
    {
      id: "ballard-accuser", name: "Ballard’s accuser", aliases: ["the woman", "the young woman"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County", "sheriff’s office"],
      description: "A woman whom Ballard finds injured beside the road and carries toward town; she later accuses him of rape and fights him in the sheriff’s office.",
      references: [
        { book: "cog", locator: "Part I, §16, pp. 46–47", note: "Ballard finds her beside the road" },
        { book: "cog", locator: "Part I, §18, pp. 51–55", note: "Complaint and confrontation" }
      ]
    },
    {
      id: "frog-mountain-couple", name: "The couple in the car", aliases: ["the dead girl", "the dead man", "Ballard’s first corpse"], kind: "unnamed", prominence: "major",
      books: ["cog"], dates: ["December before April 1965"], locations: ["Frog Mountain turnaround", "Ballard’s cabin"],
      description: "A young couple found dead in an idling car. Ballard removes the woman’s body and makes it the center of his hidden domestic fantasy.",
      references: [
        { book: "cog", locator: "Part II, §26, pp. 84–92", note: "Discovery of the car and bodies" },
        { book: "cog", locator: "Part II, §§27–29, pp. 93–105", note: "The body concealed at the cabin" }
      ]
    },
    {
      id: "dump-daughter-child", name: "The idiot child", aliases: ["the child", "the cretin"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["the dumpkeeper’s house"],
      description: "A disabled child in the dumpkeeper’s household who remains in the room when Ballard kills one of the daughters and sets the house afire.",
      references: [{ book: "cog", locator: "Part II, §34, pp. 115–120", note: "Witness to the attack and fire" }]
    },
    {
      id: "later-young-couple-cog", name: "The later young couple", aliases: ["the boy and girl in the truck"], kind: "unnamed", prominence: "secondary",
      books: ["cog"], dates: ["before April 1965"], locations: ["a mountain road in Sevier County"],
      description: "A courting pair surprised by Ballard in a parked truck. He kills the boy and attacks the girl, but the wounded boy escapes with the vehicle.",
      references: [{ book: "cog", locator: "Part III, §43, pp. 149–153", note: "Attack beside the mountain road" }]
    },
    {
      id: "tom-davis-cog", name: "Tom Davis", aliases: ["Sheriff Davis"], kind: "historical", prominence: "minor",
      books: ["cog"], dates: ["late nineteenth century", "sheriff by 1899"], locations: ["Sevier County", "Nashville", "Knoxville"],
      description: "A remembered Sevier County deputy and sheriff credited in Mr Wade’s flood-time story with breaking the White Caps and overseeing the 1899 hanging of two members.",
      references: [{ book: "cog", locator: "Part III, §45, pp. 165–168", note: "Mr Wade’s county history" }]
    },
    {
      id: "suzie-cog", name: "Suzie", aliases: ["Bill’s bird dog"], kind: "animal", prominence: "minor",
      books: ["cog"], dates: ["before April 1965"], locations: ["Sevier County hunting country"],
      description: "A dog in a local hunting anecdote, memorable because her supposed illness becomes the story’s running joke.",
      references: [{ book: "cog", locator: "Part I, §17, pp. 48–49", note: "The bird-dog story" }]
    },
    {
      id: "the-kid", name: "The kid", aliases: ["the man", "the child"], kind: "unnamed", prominence: "principal",
      books: ["bm"], dates: ["born 1833", "rides west in 1849", "Fort Griffin in 1878"],
      locations: ["Tennessee", "Nacogdoches", "San Antonio", "Chihuahua", "Sonora", "the Colorado River", "Fort Griffin"],
      description: "The nameless Tennessee runaway at the center of Blood Meridian. He joins Captain White’s filibusters and Glanton’s scalp hunters, survives the gang’s destruction, and reappears decades later as the man.",
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
      description: "The gigantic, hairless polymath of Glanton’s gang: linguist, natural philosopher, performer, manipulator, and architect of the novel’s most explicit creed of domination and war.",
      references: [
        { book: "bm", locator: "Chapter I", note: "Accusation against Reverend Green" },
        { book: "bm", locator: "Chapters VII–XIV", note: "With Glanton’s gang and the ledger" },
        { book: "bm", locator: "Chapters XX–XXIII", note: "Pursuit of the kid and final appearance" }
      ]
    },
    {
      id: "john-joel-glanton", name: "John Joel Glanton", aliases: ["Glanton", "Captain Glanton"], kind: "historical", prominence: "principal",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "San Diego", "Yuma ferry"],
      description: "The historical Texan scalp hunter fictionalized as captain of the gang. His contracts, raids, and seizure of the Yuma ferry drive the company toward annihilation.",
      references: [
        { book: "bm", locator: "Chapter VI", note: "The contract with Governor Trías" },
        { book: "bm", locator: "Chapters VII–XVIII", note: "Command of the scalp-hunting company" },
        { book: "bm", locator: "Chapter XIX", note: "Rule and destruction of the ferry settlement" }
      ]
    },
    {
      id: "louis-toadvine", name: "Louis Toadvine", aliases: ["Toadvine"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Nacogdoches", "Chihuahua", "Sonora", "Los Angeles"],
      description: "A branded, mutilated fugitive first met by the kid in Nacogdoches. He becomes the kid’s recurring companion, joins Glanton’s gang, and is later hanged in Los Angeles.",
      references: [
        { book: "bm", locator: "Chapter I", note: "Fight, alliance, and hotel fire" },
        { book: "bm", locator: "Chapters V–XX", note: "Return in Chihuahua and service with Glanton" },
        { book: "bm", locator: "Chapter XXII", note: "Seen in Los Angeles" }
      ]
    },
    {
      id: "ben-tobin", name: "Ben Tobin", aliases: ["Tobin", "the expriest", "the priest"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Colorado River desert", "San Diego"],
      description: "An Irish former novice and veteran of Glanton’s company. He recounts the judge’s arrival, warns the kid against him, and shares the kid’s flight after the Yuma massacre.",
      references: [
        { book: "bm", locator: "Chapters VII–X", note: "Introduced and narrates the judge’s gunpowder feat" },
        { book: "bm", locator: "Chapters XX–XXII", note: "Flight from the judge and arrival in San Diego" }
      ]
    },
    {
      id: "david-brown-bm", name: "David Brown", aliases: ["Davy Brown", "Brown"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "San Diego", "Los Angeles"],
      description: "A hard and volatile member of Glanton’s gang. He survives repeated campaigns, is jailed after a confrontation in San Diego, and is later executed in Los Angeles.",
      references: [
        { book: "bm", locator: "Chapters VII–XVII", note: "Campaigns with Glanton’s company" },
        { book: "bm", locator: "Chapter XIX", note: "San Diego arrest" },
        { book: "bm", locator: "Chapter XXII", note: "Fate in Los Angeles" }
      ]
    },
    {
      id: "black-jackson", name: "Black Jackson", aliases: ["John Jackson", "the black Jackson", "Blackie"], kind: "person", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Yuma ferry"],
      description: "One of two gang members named John Jackson. He kills his racist white namesake and remains a conspicuous member of the company until the Yuma attack.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "The two Jacksons introduced" },
        { book: "bm", locator: "Chapter VIII", note: "Killing of White Jackson" },
        { book: "bm", locator: "Chapter XIX", note: "At the Yuma ferry" }
      ]
    },
    {
      id: "white-jackson", name: "White Jackson", aliases: ["John Jackson", "the white Jackson"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["dies 1849"], locations: ["Chihuahua", "northern Mexico"],
      description: "The white member of the gang who shares John Jackson’s name. His sustained racist provocation ends when Black Jackson kills him.",
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
      description: "Leader of an illegal American filibustering expedition into Mexico. He recruits the kid with expansionist rhetoric before Apache warriors destroy the company.",
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
      description: "The gang’s doctor, a sardonic presence during the campaigns who is killed in the Yuma uprising.",
      references: [
        { book: "bm", locator: "Chapter IX", note: "Treats—or declines to treat—the wounded" },
        { book: "bm", locator: "Chapter XIX", note: "Death at the ferry" }
      ]
    },
    {
      id: "delaware-guides", name: "The Delaware guides", aliases: ["the Delawares"], kind: "unnamed", prominence: "major",
      books: ["bm"], dates: ["1849–1850"], locations: ["Chihuahua", "Sonora", "Arizona", "Colorado River"],
      description: "A small group of Delaware scouts and fighters who guide Glanton’s company, track enemies, and suffer heavily across the campaigns.",
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
      description: "A formidable woman in San Diego who washes, clothes, and feeds James Robert Bell and rebukes Cloyce for exploiting him.",
      references: [{ book: "bm", locator: "Chapter XVIII", note: "Care of James Robert Bell" }]
    },
    {
      id: "speyer-bm", name: "Speyer", aliases: ["the Prussian arms dealer"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Chihuahua City"],
      description: "A Prussian Jewish merchant who sells Glanton’s men a case of Colt revolvers and negotiates nervously under the captain’s pressure.",
      references: [{ book: "bm", locator: "Chapter VII", note: "Sale of the revolvers" }]
    },
    {
      id: "reverend-green", name: "Reverend Green", aliases: ["the Reverend"], kind: "person", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Nacogdoches, Texas"],
      description: "A traveling revival preacher whose tent meeting is destroyed when Judge Holden invents sensational accusations against him.",
      references: [{ book: "bm", locator: "Chapter I", note: "The judge’s false accusation" }]
    },
    {
      id: "mennonite-bm", name: "The Mennonite", aliases: ["the old Mennonite"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Laredito"],
      description: "An old drinker who warns Captain White’s recruits that their expedition will end in disaster across the river.",
      references: [{ book: "bm", locator: "Chapter III", note: "Warning in the cantina" }]
    },
    {
      id: "hermit-bm", name: "The hermit", aliases: ["the old hermit"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["East Texas"],
      description: "A solitary former slaver who shelters the kid for a night and speaks bitterly about human hearts and racial violence.",
      references: [{ book: "bm", locator: "Chapter II", note: "Night in the hermit’s hut" }]
    },
    {
      id: "angel-trias", name: "Ángel Trías", aliases: ["Governor Trías", "Trias"], kind: "historical", prominence: "secondary",
      books: ["bm"], dates: ["governor of Chihuahua in 1849"], locations: ["Chihuahua City"],
      description: "The governor of Chihuahua who contracts Glanton’s company for Apache scalps and publicly rewards the returning hunters.",
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
      description: "A teenage bonepicker who challenges the man beside a prairie fire and is killed, marking the man’s return to the violence of his youth.",
      references: [{ book: "bm", locator: "Chapter XXIII", note: "Night with the bonepickers" }]
    },
    {
      id: "juggler-couple-bm", name: "The juggler and fortune-teller", aliases: ["the juggler", "the old woman", "the soothsayer"], kind: "unnamed", prominence: "secondary",
      books: ["bm"], dates: ["1849"], locations: ["Janos", "Nacori"],
      description: "Itinerant performers whose tricks and tarot-like readings provide ominous commentaries on members of Glanton’s company.",
      references: [
        { book: "bm", locator: "Chapter VII", note: "Performance and readings at Janos" },
        { book: "bm", locator: "Chapter XIII", note: "A later encounter" }
      ]
    },
    {
      id: "sergeant-aguilar", name: "Sergeant Aguilar", aliases: ["Aguilar"], kind: "person", prominence: "minor",
      books: ["bm"], dates: ["1849"], locations: ["Janos"],
      description: "A Mexican sergeant who confronts the armed Americans at Janos and is theatrically disarmed by the judge’s diplomacy.",
      references: [{ book: "bm", locator: "Chapter VII", note: "Encounter at Janos" }]
    },
    {
      id: "lieutenant-couts", name: "Lieutenant Cave J. Couts", aliases: ["Lieutenant Couts", "Couts"], kind: "historical", prominence: "minor",
      books: ["bm"], dates: ["1850"], locations: ["Tucson"],
      description: "The U.S. Army lieutenant commanding Tucson’s small garrison when Glanton’s gang arrives amid a tense Apache demand for whiskey.",
      references: [{ book: "bm", locator: "Chapter XVI", note: "Encounter at the Tucson garrison" }]
    },
    {
      id: "mangas-colorado", name: "Mangas Colorado", aliases: ["Mangas"], kind: "historical", prominence: "minor",
      books: ["bm"], dates: ["1850"], locations: ["Tucson", "Santa Cruz valley"],
      description: "The Apache leader who parleyes with Glanton after a collision involving one of his riders, then presses the Americans for whiskey near Tucson.",
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
