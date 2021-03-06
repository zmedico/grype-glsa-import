package bdb

import (
	"fmt"
	"io"
	"os"
)

var validPageSizes = map[uint32]struct{}{
	512:   {},
	1024:  {},
	2048:  {},
	4096:  {},
	8192:  {},
	16384: {},
	32768: {},
	65536: {},
}

type BerkeleyDB struct {
	file         *os.File
	HashMetadata *HashMetadataPage
}

type Entry struct {
	Value []byte
	Err   error
}

func Open(path string) (*BerkeleyDB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// read just a bit in to parse at least the metadata...
	metadataBuff := make([]byte, 512)
	_, err = file.Read(metadataBuff)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek db file: %w", err)
	}

	hashMetadata, err := ParseHashMetadataPage(metadataBuff)
	if err != nil {
		return nil, err
	}

	if _, ok := validPageSizes[hashMetadata.PageSize]; !ok {
		return nil, fmt.Errorf("unexpected page size: %+v", hashMetadata.PageSize)
	}

	return &BerkeleyDB{
		file:         file,
		HashMetadata: hashMetadata,
	}, nil

}

func (db *BerkeleyDB) Read() <-chan Entry {
	entries := make(chan Entry)

	go func() {
		defer close(entries)

		// the first content entry (idx=0) is the db metadata, skip to the first real entry and keep reading content values
		for pageNum := uint32(1); pageNum <= db.HashMetadata.LastPageNo; pageNum++ {
			pageData, err := slice(db.file, int(db.HashMetadata.PageSize))
			if err != nil {
				entries <- Entry{
					Err: err,
				}
				return
			}

			// keep track of the start of the next page for the next iteration...
			endOfPageOffset, err := db.file.Seek(0, io.SeekCurrent)
			if err != nil {
				entries <- Entry{
					Err: err,
				}
				return
			}

			hashPageHeader, err := ParseHashPage(pageData)
			if err != nil {
				entries <- Entry{
					Err: err,
				}
				return
			}

			if hashPageHeader.PageType != HashPageType {
				// skip over pages that do not have hash values
				continue
			}

			hashPageIndexes, err := HashPageValueIndexes(pageData, hashPageHeader.NumEntries)
			if err != nil {
				entries <- Entry{
					Err: err,
				}
				return
			}

			for _, hashPageIndex := range hashPageIndexes {
				// the first byte is the page type, so we can peek at it first before parsing further...
				valuePageType := pageData[hashPageIndex]

				// Only Overflow pages contain package data, skip anything else.
				if valuePageType != HashOffIndexPageType {
					continue
				}

				// Traverse the page to concatenate the data that may span multiple pages.
				valueContent, err := HashPageValueContent(
					db.file,
					pageData,
					hashPageIndex,
					db.HashMetadata.PageSize,
				)

				entries <- Entry{
					Value: valueContent,
					Err:   err,
				}

				if err != nil {
					return
				}
			}

			// go back to the start of the next page for reading...
			_, err = db.file.Seek(endOfPageOffset, io.SeekStart)
			if err != nil {
				entries <- Entry{
					Err: err,
				}
				return
			}
		}

	}()

	return entries
}
