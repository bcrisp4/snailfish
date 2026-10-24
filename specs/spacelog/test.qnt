module spacelogTest {
  import spacelog(DEVS = Set(1, 2), BAD = Set(), MAX_REC = 6, MAX_ATTACKS = 3,
                  FAULTS = Set("fork"), BUG = "none").* from "./model"
  run placeholderTest = init
}
