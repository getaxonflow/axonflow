// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"slices"
	"sort"

	"axonflow/platform/orchestrator/media"
)

// mediaSignalKeys names, for each capability, the media.* signals it states, in
// the order stateSignals takes their values. It is the one vocabulary: every
// signal mediaSignalsFromResults writes is written through it.
var mediaSignalKeys = map[string][]string{
	media.ScanContentSafety: {"nsfw_score", "violence_score", "content_safe"},
	media.ScanFaces:         {"has_faces", "face_count", "has_biometric_data"},
	media.ScanDocument:      {"document_type", "is_sensitive_document"},
	media.ScanPII:           {"has_pii", "pii_types"},
	media.ScanText:          {"has_extracted_text", "extracted_text_length"},
}

// mediaSignalsFromResults is the request's media analysis as the policy
// signals read it (context.media_analysis and the process's own
// req.mediaAnalysis, which dynamic_fact_producer.go mediaSignal states).
//
// A signal is written only when the capability that produces it RAN on every
// attached item (AggregatedMediaResult.Scanned); its value is the worst case
// across the items. A signal whose capability did not run on some item is
// OMITTED, so it reads UNKNOWN, never its zero: before #4249 row 5705208432
// every signal was seeded with a safe zero whenever any result existed, so an
// image with no analyzer registered - every shipped image - stated has_pii
// false, nsfw_score 0 and the rest, and the five shipped sys_media_* controls
// were decided on values no detector produced.
func mediaSignalsFromResults(results []*media.AggregatedMediaResult) map[string]interface{} {
	signals := map[string]interface{}{}
	if len(results) == 0 {
		return signals
	}
	ranOnAll := func(capability string) bool {
		for _, r := range results {
			if r == nil || !slices.Contains(r.Scanned, capability) {
				return false
			}
		}
		return true
	}

	if ranOnAll(media.ScanContentSafety) {
		nsfw, violence, safe := 0.0, 0.0, true
		for _, r := range results {
			if r.NSFWScore > nsfw {
				nsfw = r.NSFWScore
			}
			if r.ViolenceScore > violence {
				violence = r.ViolenceScore
			}
			if !r.ContentSafe {
				safe = false
			}
		}
		stateSignals(signals, media.ScanContentSafety, nsfw, violence, safe)
	}
	if ranOnAll(media.ScanFaces) {
		hasFaces, count, biometric := false, 0, false
		for _, r := range results {
			hasFaces = hasFaces || r.HasFaces
			count += r.FaceCount
			biometric = biometric || r.HasBiometricData
		}
		stateSignals(signals, media.ScanFaces, hasFaces, count, biometric)
	}
	if ranOnAll(media.ScanDocument) {
		docType, sensitive := "", false
		for _, r := range results {
			if r.DocumentType != "" {
				docType = r.DocumentType
			}
			sensitive = sensitive || r.IsSensitiveDocument
		}
		stateSignals(signals, media.ScanDocument, docType, sensitive)
	}
	if ranOnAll(media.ScanPII) {
		hasPII := false
		set := map[string]bool{}
		for _, r := range results {
			hasPII = hasPII || r.HasPII
			for _, pt := range r.PIITypes {
				set[pt] = true
			}
		}
		types := make([]string, 0, len(set))
		for pt := range set {
			types = append(types, pt)
		}
		sort.Strings(types)
		stateSignals(signals, media.ScanPII, hasPII, types)
	}
	if ranOnAll(media.ScanText) {
		hasText, length := false, 0
		for _, r := range results {
			if r.ExtractedText != "" {
				hasText = true
				length += len(r.ExtractedText)
			}
		}
		stateSignals(signals, media.ScanText, hasText, length)
	}
	return signals
}

// stateSignals writes capability's signals, named by mediaSignalKeys, from
// values in the same order. A count that does not match the vocabulary states
// none of them, so they read UNKNOWN rather than landing under the wrong key;
// the DeepEqual cells in media_signals_test.go turn that red.
func stateSignals(signals map[string]interface{}, capability string, values ...interface{}) {
	keys := mediaSignalKeys[capability]
	if len(keys) != len(values) {
		return
	}
	for i, k := range keys {
		signals[k] = values[i]
	}
}
