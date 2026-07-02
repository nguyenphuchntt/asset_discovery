package asset

import "time"

type EventType string

const (
	EventAssetCreated   EventType = "asset_created"
	EventAssetUpdated   EventType = "asset_updated"
	EventStatusOnline   EventType = "status_online"
	EventStatusOffline  EventType = "status_offline"
	EventIdentityMerged EventType = "identity_merged"
)

type Event struct {
	Type    EventType
	AssetID AssetID
	At      time.Time
	Source  ObservationSource
	Detail  string
}

func newEvent(t EventType, id AssetID, at time.Time, source ObservationSource, detail string) Event {
	return Event{
		Type:    t,
		AssetID: id,
		At:      at,
		Source:  source,
		Detail:  detail,
	}
}
