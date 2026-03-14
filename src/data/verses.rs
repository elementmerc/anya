// Ányá — Bible verse pool (NLT)
// Single shared source used by both the CLI `anya verse` subcommand and the
// Tauri `get_random_verse` command.  No duplication across front/back end.

/// 30 NLT verses as (text, reference) pairs.
pub const VERSES: &[(&str, &str)] = &[
    (
        "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.",
        "John 3:16",
    ),
    (
        "I can do everything through Christ, who gives me strength.",
        "Philippians 4:13",
    ),
    (
        "Trust in the Lord with all your heart; do not depend on your own understanding. Seek his will in all you do, and he will show you which path to take.",
        "Proverbs 3:5-6",
    ),
    (
        "The Lord is my shepherd; I have all that I need.",
        "Psalm 23:1",
    ),
    (
        "And we know that God causes everything to work together for the good of those who love God and are called according to his purpose for them.",
        "Romans 8:28",
    ),
    (
        "For I know the plans I have for you, says the Lord. They are plans for good and not for disaster, to give you a future and a hope.",
        "Jeremiah 29:11",
    ),
    (
        "Don't be afraid, for I am with you. Don't be discouraged, for I am your God. I will strengthen you and help you. I will hold you up with my victorious right hand.",
        "Isaiah 41:10",
    ),
    (
        "Jesus told him, 'I am the way, the truth, and the life. No one can come to the Father except through me.'",
        "John 14:6",
    ),
    (
        "Even when I walk through the darkest valley, I will not be afraid, for you are close beside me. Your rod and your staff protect and comfort me.",
        "Psalm 23:4",
    ),
    (
        "But those who trust in the Lord will find new strength. They will soar high on wings like eagles. They will run and not grow weary. They will walk and not faint.",
        "Isaiah 40:31",
    ),
    (
        "This is my command—be strong and courageous! Do not be afraid or discouraged. For the Lord your God is with you wherever you go.",
        "Joshua 1:9",
    ),
    (
        "For nothing will be impossible with God.",
        "Luke 1:37",
    ),
    (
        "Come to me, all of you who are weary and carry heavy burdens, and I will give you rest.",
        "Matthew 11:28",
    ),
    (
        "The Lord himself will fight for you. Just stay calm.",
        "Exodus 14:14",
    ),
    (
        "Give all your worries and cares to God, for he cares about you.",
        "1 Peter 5:7",
    ),
    (
        "Don't worry about anything; instead, pray about everything. Tell God what you need, and thank him for all he has done.",
        "Philippians 4:6",
    ),
    (
        "The Lord is my light and my salvation—so why should I be afraid? The Lord is my fortress, protecting me from danger, so why should I tremble?",
        "Psalm 27:1",
    ),
    (
        "Love is patient and kind. Love is not jealous or boastful or proud or rude.",
        "1 Corinthians 13:4-5",
    ),
    (
        "But seek first the Kingdom of God and his righteousness, and all these things will be given to you as well.",
        "Matthew 6:33",
    ),
    (
        "For the word of God is alive and powerful. It is sharper than the sharpest two-edged sword.",
        "Hebrews 4:12",
    ),
    (
        "No, despite all these things, overwhelming victory is ours through Christ, who loved us.",
        "Romans 8:37",
    ),
    (
        "So now there is no condemnation for those who belong to Christ Jesus.",
        "Romans 8:1",
    ),
    (
        "What is impossible for people is possible with God.",
        "Luke 18:27",
    ),
    (
        "I am leaving you with a gift—peace of mind and heart. And the peace I give is a gift the world cannot give. So don't be troubled or afraid.",
        "John 14:27",
    ),
    (
        "The Lord bless you and keep you. The Lord smile on you and be gracious to you. The Lord show you his favor and give you his peace.",
        "Numbers 6:24-26",
    ),
    (
        "Your word is a lamp to guide my feet and a light for my path.",
        "Psalm 119:105",
    ),
    (
        "Yet I still dare to hope when I remember this: The faithful love of the Lord never ends! His mercies never cease.",
        "Lamentations 3:21-22",
    ),
    (
        "Look! I stand at the door and knock. If you hear my voice and open the door, I will come in, and we will share a meal together as friends.",
        "Revelation 3:20",
    ),
    (
        "For God has not given us a spirit of fear and timidity, but of power, love, and self-discipline.",
        "2 Timothy 1:7",
    ),
    (
        "And let the peace that comes from Christ rule in your hearts. For as members of one body you are called to live in peace. And always be thankful.",
        "Colossians 3:15",
    ),
];

/// Pick a verse index using current time as a lightweight seed.
/// No `rand` crate required.
pub fn verse_index() -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs as usize) % VERSES.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verse_pool_size() {
        assert_eq!(VERSES.len(), 30, "Verse pool must contain exactly 30 verses");
    }

    #[test]
    fn test_verse_pool_contains_john_316() {
        let has_john_316 = VERSES
            .iter()
            .any(|(_, reference)| reference.contains("John 3:16"));
        assert!(has_john_316, "Pool must contain John 3:16");
    }

    #[test]
    fn test_verse_output_format() {
        // Every verse must have non-empty text and a reference that looks like
        // "Book Chapter:Verse" or "Book Chapter:Verse-Verse".
        for (text, reference) in VERSES {
            assert!(!text.is_empty(), "Verse text must not be empty");
            assert!(!reference.is_empty(), "Verse reference must not be empty");
            // Reference must contain a colon (e.g. "John 3:16")
            assert!(
                reference.contains(':'),
                "Reference '{reference}' must contain a colon"
            );
        }
    }

    #[test]
    fn test_random_verse_returns_valid_entry() {
        // Call verse_index 100 times — each result must be a valid index.
        for _ in 0..100 {
            let idx = verse_index();
            assert!(
                idx < VERSES.len(),
                "verse_index() returned out-of-bounds index {idx}"
            );
            let (text, reference) = VERSES[idx];
            assert!(!text.is_empty());
            assert!(!reference.is_empty());
        }
    }

    #[test]
    fn test_all_verses_have_reference() {
        for (i, (text, reference)) in VERSES.iter().enumerate() {
            assert!(
                !text.is_empty(),
                "Verse at index {i} has empty text"
            );
            assert!(
                !reference.is_empty(),
                "Verse at index {i} has empty reference"
            );
        }
    }
}
