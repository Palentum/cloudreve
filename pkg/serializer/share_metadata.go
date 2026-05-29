package serializer

// ShareMetadataResponse is the response body for share file B2 metadata.
type ShareMetadataResponse struct {
	Items []ShareMetadataItem `json:"items"`
}

// ShareMetadataItem contains database and Backblaze B2 metadata for one shared file.
type ShareMetadataItem struct {
	ObjectPath  string  `json:"object_path"`
	Name        string  `json:"name"`
	Size        uint64  `json:"size"`
	ContentType string  `json:"content_type"`
	Hash        *string `json:"hash"`
	HashType    *string `json:"hash_type"`
}
