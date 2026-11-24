package rebac

// memStore is an in-memory tuple set keyed by "objType:objID#relation".
type memStore map[string][]tuple

func (m memStore) fetch(objType, objID, relation string) ([]tuple, error) {
	return m[objType+":"+objID+"#"+relation], nil
}

func check(m memStore, objType, objID, relation, userID string) bool {
	ok, _, _ := resolve(m.fetch, objType, objID, relation, userID, map[string]int{}, 0)
	return ok
}
