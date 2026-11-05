package cli

// valueFDKindOK is never true on Windows: a child gets no numbered descriptor
// there, and `prompt --value` is refused before this is asked.
func valueFDKindOK(int) bool { return false }
