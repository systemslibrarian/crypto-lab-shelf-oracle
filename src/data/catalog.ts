/**
 * The shelf: 64 public-domain works, with real authors, real first-publication
 * dates and real Library of Congress CLASS letters.
 *
 * Class letters only — not full call numbers. A call number like `PS3527.A15 P3`
 * encodes a cutter for a specific edition held by a specific library, and
 * inventing sixty-four of those would be putting fabricated bibliographic data
 * on a page whose entire subject is not lying to people. The class letter is a
 * real, checkable fact about where a work sits in the schedule.
 *
 * Sixty-four is not decoration. The selection vector has one ciphertext per
 * shelf position, the server folds one plaintext multiplication per shelf
 * position, and both costs are on screen — so the shelf length is a parameter of
 * the protocol, not a page-size choice.
 */

export interface ShelfEntry {
  /** Shelf position. Also the index the PIR query hides. */
  readonly id: number;
  readonly title: string;
  readonly author: string;
  /** First publication, or best-attested composition date for pre-print works. */
  readonly year: string;
  /** Library of Congress class letter. */
  readonly lcClass: string;
  /** What that class letter covers. */
  readonly className: string;
  /** One factual sentence. */
  readonly note: string;
}

export const CATALOG: readonly ShelfEntry[] = [
  { id: 0, title: 'Pride and Prejudice', author: 'Jane Austen', year: '1813', lcClass: 'PR', className: 'English literature', note: 'A novel of manners in Regency England, published anonymously as "by the author of Sense and Sensibility".' },
  { id: 1, title: 'Moby-Dick; or, The Whale', author: 'Herman Melville', year: '1851', lcClass: 'PS', className: 'American literature', note: 'A whaling voyage narrated by Ishmael, interleaved with chapters of cetology and stagecraft.' },
  { id: 2, title: 'Frankenstein; or, The Modern Prometheus', author: 'Mary Shelley', year: '1818', lcClass: 'PR', className: 'English literature', note: 'Written after a ghost-story challenge at Lake Geneva; the 1818 and 1831 texts differ substantially.' },
  { id: 3, title: 'Jane Eyre', author: 'Charlotte Bronte', year: '1847', lcClass: 'PR', className: 'English literature', note: 'A first-person account of a governess, first issued under the pen name Currer Bell.' },
  { id: 4, title: 'Wuthering Heights', author: 'Emily Bronte', year: '1847', lcClass: 'PR', className: 'English literature', note: 'A nested frame narrative of two Yorkshire households, published as by Ellis Bell.' },
  { id: 5, title: 'Great Expectations', author: 'Charles Dickens', year: '1861', lcClass: 'PR', className: 'English literature', note: 'Serialised weekly in All the Year Round; Dickens replaced its original ending before book publication.' },
  { id: 6, title: 'Bleak House', author: 'Charles Dickens', year: '1853', lcClass: 'PR', className: 'English literature', note: 'Alternates a third-person present tense with Esther Summerson’s retrospective narration, around a Chancery suit.' },
  { id: 7, title: 'Middlemarch: A Study of Provincial Life', author: 'George Eliot', year: '1872', lcClass: 'PR', className: 'English literature', note: 'Published in eight parts; interlocks several plots in a Midlands town around the 1832 Reform Act.' },
  { id: 8, title: 'Dracula', author: 'Bram Stoker', year: '1897', lcClass: 'PR', className: 'English literature', note: 'An epistolary novel assembled from journals, letters, telegrams and phonograph transcripts.' },
  { id: 9, title: 'The Picture of Dorian Gray', author: 'Oscar Wilde', year: '1890', lcClass: 'PR', className: 'English literature', note: 'First printed in Lippincott’s Monthly Magazine; expanded with a preface for the 1891 book edition.' },
  { id: 10, title: 'Heart of Darkness', author: 'Joseph Conrad', year: '1899', lcClass: 'PR', className: 'English literature', note: 'Serialised in Blackwood’s Magazine; a frame narrative told aboard a yawl on the Thames.' },
  { id: 11, title: 'The Time Machine', author: 'H. G. Wells', year: '1895', lcClass: 'PR', className: 'English literature', note: 'Introduced the phrase "time machine" to English and framed time as a fourth dimension of travel.' },
  { id: 12, title: 'Treasure Island', author: 'Robert Louis Stevenson', year: '1883', lcClass: 'PR', className: 'English literature', note: 'Serialised in Young Folks as "The Sea Cook" before appearing as a book.' },
  { id: 13, title: 'Gulliver’s Travels', author: 'Jonathan Swift', year: '1726', lcClass: 'PR', className: 'English literature', note: 'Published anonymously as Travels into Several Remote Nations of the World, in four parts.' },
  { id: 14, title: 'Robinson Crusoe', author: 'Daniel Defoe', year: '1719', lcClass: 'PR', className: 'English literature', note: 'Presented on its title page as a true account written by the castaway himself.' },
  { id: 15, title: 'The Life and Opinions of Tristram Shandy', author: 'Laurence Sterne', year: '1759', lcClass: 'PR', className: 'English literature', note: 'Issued in nine volumes over eight years, including a marbled page and a wholly black one.' },
  { id: 16, title: 'Paradise Lost', author: 'John Milton', year: '1667', lcClass: 'PR', className: 'English literature', note: 'An epic in blank verse, first published in ten books and rearranged into twelve in 1674.' },
  { id: 17, title: 'The Canterbury Tales', author: 'Geoffrey Chaucer', year: 'c. 1400', lcClass: 'PR', className: 'English literature', note: 'An unfinished frame collection in Middle English, surviving in more than eighty manuscripts.' },
  { id: 18, title: 'Leaves of Grass', author: 'Walt Whitman', year: '1855', lcClass: 'PS', className: 'American literature', note: 'Self-published in twelve poems and revised across six editions until 1892.' },
  { id: 19, title: 'Walden; or, Life in the Woods', author: 'Henry David Thoreau', year: '1854', lcClass: 'PS', className: 'American literature', note: 'Compresses two years beside Walden Pond into the cycle of a single year.' },
  { id: 20, title: 'The Scarlet Letter', author: 'Nathaniel Hawthorne', year: '1850', lcClass: 'PS', className: 'American literature', note: 'Opens with "The Custom-House", a sketch framing the novel as an edited found document.' },
  { id: 21, title: 'Adventures of Huckleberry Finn', author: 'Mark Twain', year: '1884', lcClass: 'PS', className: 'American literature', note: 'Published first in the United Kingdom; written in several distinguished regional dialects.' },
  { id: 22, title: 'The Awakening', author: 'Kate Chopin', year: '1899', lcClass: 'PS', className: 'American literature', note: 'A novel of a Louisiana Creole household, badly received on publication and recovered in the 1960s.' },
  { id: 23, title: 'The Souls of Black Folk', author: 'W. E. B. Du Bois', year: '1903', lcClass: 'E', className: 'History of the Americas', note: 'Fourteen essays introducing the terms "double consciousness" and "the veil".' },
  { id: 24, title: 'Narrative of the Life of Frederick Douglass', author: 'Frederick Douglass', year: '1845', lcClass: 'E', className: 'History of the Americas', note: 'The first of three autobiographies; published with authenticating prefaces by Garrison and Phillips.' },
  { id: 25, title: 'Uncle Tom’s Cabin', author: 'Harriet Beecher Stowe', year: '1852', lcClass: 'PS', className: 'American literature', note: 'Serialised in The National Era through 1851–52 before book publication.' },
  { id: 26, title: 'The Federalist', author: 'Hamilton, Madison and Jay', year: '1788', lcClass: 'JK', className: 'Political institutions, United States', note: 'Eighty-five essays published under the signature "Publius" arguing for ratification.' },
  { id: 27, title: 'Common Sense', author: 'Thomas Paine', year: '1776', lcClass: 'JC', className: 'Political theory', note: 'Issued anonymously in Philadelphia in January 1776 and reprinted in enormous numbers.' },
  { id: 28, title: 'Democracy in America', author: 'Alexis de Tocqueville', year: '1835', lcClass: 'JK', className: 'Political institutions, United States', note: 'Written after a nine-month tour commissioned to study American prisons; second volume 1840.' },
  { id: 29, title: 'On Liberty', author: 'John Stuart Mill', year: '1859', lcClass: 'JC', className: 'Political theory', note: 'States the harm principle: power may be used against a member of society only to prevent harm to others.' },
  { id: 30, title: 'Leviathan', author: 'Thomas Hobbes', year: '1651', lcClass: 'JC', className: 'Political theory', note: 'Its frontispiece composes the sovereign’s body out of the bodies of the governed.' },
  { id: 31, title: 'Two Treatises of Government', author: 'John Locke', year: '1689', lcClass: 'JC', className: 'Political theory', note: 'Published anonymously; the first treatise refutes Filmer, the second sets out consent and property.' },
  { id: 32, title: 'An Inquiry into the Wealth of Nations', author: 'Adam Smith', year: '1776', lcClass: 'HB', className: 'Economic theory', note: 'Opens with the division of labour observed in a pin manufactory.' },
  { id: 33, title: 'Capital, Volume I', author: 'Karl Marx', year: '1867', lcClass: 'HB', className: 'Economic theory', note: 'The only volume Marx published himself; Engels edited volumes II and III from notebooks.' },
  { id: 34, title: 'The Prince', author: 'Niccolo Machiavelli', year: '1532', lcClass: 'JC', className: 'Political theory', note: 'Written around 1513 and printed five years after its author’s death.' },
  { id: 35, title: 'Meditations', author: 'Marcus Aurelius', year: 'c. 180', lcClass: 'B', className: 'Philosophy', note: 'Private Greek notebooks by a Roman emperor, with no evidence they were meant for readers.' },
  { id: 36, title: 'Nicomachean Ethics', author: 'Aristotle', year: 'c. 340 BCE', lcClass: 'B', className: 'Philosophy', note: 'Ten books on virtue as a mean and on eudaimonia as activity of the soul.' },
  { id: 37, title: 'Republic', author: 'Plato', year: 'c. 375 BCE', lcClass: 'B', className: 'Philosophy', note: 'A dialogue on justice containing the allegories of the sun, the divided line and the cave.' },
  { id: 38, title: 'Critique of Pure Reason', author: 'Immanuel Kant', year: '1781', lcClass: 'B', className: 'Philosophy', note: 'Substantially revised for the 1787 second edition; the two texts are cited as A and B.' },
  { id: 39, title: 'Thus Spoke Zarathustra', author: 'Friedrich Nietzsche', year: '1883', lcClass: 'B', className: 'Philosophy', note: 'Published in four parts, the last privately printed in forty copies.' },
  { id: 40, title: 'A Vindication of the Rights of Woman', author: 'Mary Wollstonecraft', year: '1792', lcClass: 'HQ', className: 'The family, marriage and women', note: 'Argues that women appear inferior because they are denied the same education, not by nature.' },
  { id: 41, title: 'Philosophiae Naturalis Principia Mathematica', author: 'Isaac Newton', year: '1687', lcClass: 'QA', className: 'Mathematics', note: 'States the laws of motion and universal gravitation in the geometric style of classical proof.' },
  { id: 42, title: 'On the Origin of Species', author: 'Charles Darwin', year: '1859', lcClass: 'QH', className: 'Natural history and biology', note: 'The first printing of 1,250 copies sold out on its day of issue; six editions followed.' },
  { id: 43, title: 'Elements', author: 'Euclid', year: 'c. 300 BCE', lcClass: 'QA', className: 'Mathematics', note: 'Thirteen books of definitions, postulates and propositions; Book IX proves the primes are infinite.' },
  { id: 44, title: 'Dialogue Concerning the Two Chief World Systems', author: 'Galileo Galilei', year: '1632', lcClass: 'QB', className: 'Astronomy', note: 'A four-day dialogue in Italian; its publication led directly to Galileo’s trial.' },
  { id: 45, title: 'On the Revolutions of the Heavenly Spheres', author: 'Nicolaus Copernicus', year: '1543', lcClass: 'QB', className: 'Astronomy', note: 'Printed in Nuremberg in the year of its author’s death, with an unsigned preface he did not write.' },
  { id: 46, title: 'Micrographia', author: 'Robert Hooke', year: '1665', lcClass: 'QH', className: 'Natural history and biology', note: 'Its engraved plates of a flea and a fly’s eye introduced the word "cell" to biology.' },
  { id: 47, title: 'The Interpretation of Dreams', author: 'Sigmund Freud', year: '1899', lcClass: 'BF', className: 'Psychology', note: 'Dated 1900 by its publisher; the first printing of 600 copies took eight years to sell.' },
  { id: 48, title: 'Don Quixote', author: 'Miguel de Cervantes', year: '1605', lcClass: 'PQ', className: 'Romance literatures', note: 'The second part of 1615 answers a spurious continuation published under another name.' },
  { id: 49, title: 'Les Miserables', author: 'Victor Hugo', year: '1862', lcClass: 'PQ', className: 'Romance literatures', note: 'Published simultaneously in several cities; contains a long digression on the Paris sewers.' },
  { id: 50, title: 'Madame Bovary', author: 'Gustave Flaubert', year: '1856', lcClass: 'PQ', className: 'Romance literatures', note: 'Serialised in the Revue de Paris, then prosecuted for offending public morals and acquitted.' },
  { id: 51, title: 'The Count of Monte Cristo', author: 'Alexandre Dumas', year: '1844', lcClass: 'PQ', className: 'Romance literatures', note: 'Serialised in the Journal des Debats over eighteen months, partly drawn from a police memoir.' },
  { id: 52, title: 'The Divine Comedy', author: 'Dante Alighieri', year: 'c. 1320', lcClass: 'PQ', className: 'Romance literatures', note: 'A hundred cantos in terza rima, completed shortly before the poet’s death in Ravenna.' },
  { id: 53, title: 'Crime and Punishment', author: 'Fyodor Dostoevsky', year: '1866', lcClass: 'PG', className: 'Slavic literatures', note: 'Serialised across twelve monthly instalments of The Russian Messenger.' },
  { id: 54, title: 'War and Peace', author: 'Leo Tolstoy', year: '1869', lcClass: 'PG', className: 'Slavic literatures', note: 'Begun as a novel about the Decembrists and extended backwards to the Napoleonic invasion.' },
  { id: 55, title: 'Anna Karenina', author: 'Leo Tolstoy', year: '1878', lcClass: 'PG', className: 'Slavic literatures', note: 'Serialised from 1875; the final part was published separately after an editorial dispute.' },
  { id: 56, title: 'Dead Souls', author: 'Nikolai Gogol', year: '1842', lcClass: 'PG', className: 'Slavic literatures', note: 'Subtitled a poem; Gogol burned most of the second part shortly before he died.' },
  { id: 57, title: 'Faust, Part One', author: 'Johann Wolfgang von Goethe', year: '1808', lcClass: 'PT', className: 'Germanic literatures', note: 'Worked on for some sixty years; the second part was published after Goethe’s death in 1832.' },
  { id: 58, title: 'The Metamorphosis', author: 'Franz Kafka', year: '1915', lcClass: 'PT', className: 'Germanic literatures', note: 'Kafka asked his publisher not to illustrate the insect on the cover.' },
  { id: 59, title: 'The Tale of Genji', author: 'Murasaki Shikibu', year: 'c. 1010', lcClass: 'PL', className: 'Literatures of East Asia', note: 'Fifty-four chapters written at the Heian court; no manuscript in the author’s hand survives.' },
  { id: 60, title: 'Analects', author: 'Confucius (compiled by disciples)', year: 'c. 475 BCE', lcClass: 'B', className: 'Philosophy', note: 'Twenty books of sayings assembled over generations rather than written by one hand.' },
  { id: 61, title: 'The Art of War', author: 'Sun Tzu', year: 'c. 5th century BCE', lcClass: 'U', className: 'Military science', note: 'Thirteen chapters; bamboo-slip copies found at Yinqueshan in 1972 confirmed the received text.' },
  { id: 62, title: 'One Thousand and One Nights', author: 'Anonymous, compiled', year: 'c. 1400', lcClass: 'PJ', className: 'Oriental philology and literature', note: 'A frame collection assembled over centuries; several famous tales entered it only in European editions.' },
  { id: 63, title: 'The Epic of Gilgamesh', author: 'Anonymous, Sin-leqi-unninni recension', year: 'c. 1200 BCE', lcClass: 'PJ', className: 'Oriental philology and literature', note: 'Recovered from cuneiform tablets in the library of Ashurbanipal, excavated at Nineveh in the 1850s.' },
];

/** The authored shelf's real length. */
export const CATALOG_SIZE = CATALOG.length;

/**
 * The text of one shelf record, before padding and tagging.
 *
 * This is the string the PIR answer actually returns — the whole point being
 * that a record is a record, not an availability bit.
 */
export function entryText(entry: ShelfEntry): string {
  return (
    `${entry.title} / ${entry.author}. ${entry.year}. ` +
    `LC class ${entry.lcClass} — ${entry.className}. ${entry.note}`
  );
}

/**
 * The shelf at a requested length.
 *
 * Past 64 the catalog is TILED, and the page says so where the control is: the
 * arithmetic of noise growth and server cost depends on how many records there
 * are, not on whether they are distinct, so tiling measures the real cost of a
 * longer shelf without inventing fifty more bibliographic records.
 */
export function shelfEntries(size: number): ShelfEntry[] {
  const out: ShelfEntry[] = [];
  for (let i = 0; i < size; i += 1) {
    const base = CATALOG[i % CATALOG_SIZE];
    out.push(i < CATALOG_SIZE ? base : { ...base, id: i });
  }
  return out;
}
