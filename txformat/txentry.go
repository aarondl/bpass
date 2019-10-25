package txformat

import "fmt"

// Entry is an cached entry in the store, it holds the values as currently
// known.
type Entry map[string]interface{}

// ListEntry is the way arrays are stored. It's done this way so that each
// entry has a specific uuid to make appends/deletes easy to reconcile.
type ListEntry struct {
	UUID  string `msgpack:"uuid" json:"uuid"`
	Value string `msgpack:"value" json:"value"`
}

// String returns the key's value as a string, an error occurs if the key
// was not found or of wrong type.
func (e Entry) String(key string) (string, error) {
	intf, ok := e[key]
	if !ok {
		return "", KeyNotFound{Key: key}
	}

	s, ok := intf.(string)
	if !ok {
		return "", fmt.Errorf("%s's value was not a string: %T", key, intf)
	}

	return s, nil
}

// List returns a list from a key. When we first decode a cached structure
// a list will be represented as interface{} -> []interface{} ->
// []map[string]interface{} -> []{uuid: uuid, value: value}. This function automatically
// does that conversion and resaves the value so that it's only:
// interface{} -> []listEntry
func (e Entry) List(key string) ([]ListEntry, error) {
	v, ok := e[key]
	if !ok {
		return nil, KeyNotFound{Key: key}
	}

	switch got := v.(type) {
	case []interface{}:
		// Convert each list index
		ret := make([]ListEntry, len(got))
		for i, intf := range got {

			// Here we may have a listEntry if this method has been used once
			// before
			switch gotElem := intf.(type) {
			case ListEntry:
				ret[i] = gotElem

			case map[string]interface{}:
				uuidIntf, ok := gotElem["uuid"]
				if !ok {
					return nil, fmt.Errorf(`%s[%d] list element "uuid" key does not exist: %T`, key, i, gotElem)
				}
				valIntf, ok := gotElem["value"]
				if !ok {
					return nil, fmt.Errorf(`%s[%d] list element "value" key does not exist: %T`, key, i, gotElem)
				}

				uuid, ok := uuidIntf.(string)
				if !ok {
					return nil, fmt.Errorf("%s[%d] list element uuid was not a string: %T", key, i, valIntf)
				}

				val, ok := valIntf.(string)
				if !ok {
					return nil, fmt.Errorf("%s[%d] list element value was not a string: %T", key, i, valIntf)
				}

				ret[i] = ListEntry{UUID: uuid, Value: val}
			default:
				return nil, fmt.Errorf("%s[%d] list element is not an object or listEntry: %T", key, i, intf)
			}
		}

		// This should be completely equivalent, just a better in-memory
		// representation, GC will eat the ugly maps and we'll be better for it
		e[key] = ret
		return ret, nil
	case []ListEntry:
		return got, nil
	default:
		return nil, fmt.Errorf("%s is not a list type", key)
	}
}

// SetList sets a list
func (e Entry) SetList(key string, list []ListEntry) {
	e[key] = list
}

// ListEntryValues returns only the values for a list
func ListEntryValues(list []ListEntry) []string {
	if len(list) == 0 {
		return nil
	}

	values := make([]string, len(list))
	for i := range values {
		values[i] = list[i].Value
	}

	return values
}
