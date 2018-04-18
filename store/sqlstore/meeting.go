// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sqlstore

import (
	"database/sql"
	"time"

	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
)

// meetingStore is an implementation of meeting.Store that uses an sql
// table.
type meetingStore struct {
	*backend
}

// Context implements meeting.Store.Context.
func (s *meetingStore) Context(ctx context.Context) (_ context.Context, cancel func()) {
	return ctx, func() {}
}

// Put implements meeting.Store.Put.
func (s *meetingStore) Put(_ context.Context, id, address string) error {
	return s.put(id, address, time.Now())
}

type meetingParams struct {
	argBuilder
	ID      string
	Address string
	Time    time.Time
}

// put is the internal version of Put which takes a time
// for testing purposes.
func (s *meetingStore) put(id, address string, now time.Time) error {
	params := &meetingParams{
		argBuilder: s.driver.argBuilderFunc(),

		ID:      id,
		Address: address,
		Time:    now,
	}
	_, err := s.driver.exec(s.db, tmplPutMeeting, params)
	return errgo.Mask(err)
}

// Get implements meeting.Store.Get.
func (s *meetingStore) Get(_ context.Context, id string) (string, error) {
	params := &meetingParams{
		argBuilder: s.driver.argBuilderFunc(),
		ID:         id,
	}

	var address string
	var created time.Time
	row, err := s.driver.queryRow(s.db, tmplGetMeeting, params)
	if err != nil {
		return "", errgo.Mask(err)
	}
	err = row.Scan(&address, &created)
	if errgo.Cause(err) == sql.ErrNoRows {
		return "", errgo.Newf("rendezvous not found, probably expired")
	}
	return address, errgo.Mask(err)
}

type removeMeetingParams struct {
	argBuilder
	IDs []string
}

// Remove implements meeting.Store.Remove.
func (s *meetingStore) Remove(_ context.Context, id string) (time.Time, error) {
	var created time.Time
	err := s.withTx(func(tx *sql.Tx) error {
		params := &meetingParams{
			argBuilder: s.driver.argBuilderFunc(),
			ID:         id,
		}
		row, err := s.driver.queryRow(tx, tmplGetMeeting, params)
		if err != nil {
			return errgo.Mask(err)
		}
		var address string
		err = row.Scan(&address, &created)
		if err != nil {
			return errgo.Mask(err, errgo.Is(sql.ErrNoRows))
		}
		removeParams := removeMeetingParams{
			argBuilder: s.driver.argBuilderFunc(),
			IDs:        []string{id},
		}
		params.argBuilder = s.driver.argBuilderFunc()
		_, err = s.driver.exec(tx, tmplRemoveMeetings, removeParams)
		return errgo.Mask(err)
	})
	if errgo.Cause(err) == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return created, errgo.Mask(err)
}

// RemoveOld implements meeting.Store.RemoveOld.
func (s *meetingStore) RemoveOld(_ context.Context, addr string, olderThan time.Time) (ids []string, err error) {
	err = s.withTx(func(tx *sql.Tx) error {
		params := &meetingParams{
			argBuilder: s.driver.argBuilderFunc(),
			Address:    addr,
			Time:       olderThan,
		}
		rows, err := s.driver.query(tx, tmplFindMeetings, params)
		if err != nil {
			return errgo.Mask(err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return errgo.Mask(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return errgo.Mask(err)
		}
		if len(ids) == 0 {
			return nil
		}
		removeParams := removeMeetingParams{
			argBuilder: s.driver.argBuilderFunc(),
			IDs:        ids,
		}
		_, err = s.driver.exec(tx, tmplRemoveMeetings, removeParams)
		return errgo.Mask(err)
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return ids, nil
}
