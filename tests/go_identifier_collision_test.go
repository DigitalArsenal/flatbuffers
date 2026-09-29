/*
 * Copyright 2026 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The root table's file-identifier constant is <Root>Identifier unless its
// package already declares that name (tests/go_identifier_collision). GoTest.sh
// generates the GoIdentifierCollision packages and runs this; the packages
// compiling at all is half the test.
package identifier_collision_test

import (
	"testing"

	Enum "GoIdentifierCollision/Enum"
	Plain "GoIdentifierCollision/Plain"
	Table "GoIdentifierCollision/Table"
	Twice "GoIdentifierCollision/Twice"

	flatbuffers "github.com/google/flatbuffers/go"
)

// A table TrackIdentifier beside the root table Track.
func TestTableNamedLikeTheConstant(t *testing.T) {
	if Table.TrackFileIdentifier != "TRK1" {
		t.Fatalf("TrackFileIdentifier = %q, want TRK1", Table.TrackFileIdentifier)
	}

	b := flatbuffers.NewBuilder(0)
	model := b.CreateString("constant-velocity")
	Table.TrackIdentifierStart(b)
	Table.TrackIdentifierAddModel(b, model)
	id := Table.TrackIdentifierEnd(b)
	Table.TrackStart(b)
	Table.TrackAddId(b, id)
	Table.FinishTrackBuffer(b, Table.TrackEnd(b))
	buf := b.FinishedBytes()

	if string(buf[4:8]) != "TRK1" || !Table.TrackBufferHasIdentifier(buf) {
		t.Fatalf("buffer identifier = %q, want TRK1", buf[4:8])
	}
	var ident Table.TrackIdentifier
	if Table.GetRootAsTrack(buf, 0).Id(&ident) == nil {
		t.Fatal("Track.Id is absent")
	}
	if got := string(ident.Model()); got != "constant-velocity" {
		t.Fatalf("TrackIdentifier.Model = %q, want constant-velocity", got)
	}
}

// The enum constant BeamIdentifier (BeamIdent.ifier) beside the root table Beam.
func TestEnumConstantNamedLikeTheConstant(t *testing.T) {
	if Enum.BeamFileIdentifier != "BEM1" {
		t.Fatalf("BeamFileIdentifier = %q, want BEM1", Enum.BeamFileIdentifier)
	}

	b := flatbuffers.NewBuilder(0)
	Enum.BeamStart(b)
	Enum.BeamAddIdent(b, Enum.BeamIdentifier)
	Enum.FinishBeamBuffer(b, Enum.BeamEnd(b))
	buf := b.FinishedBytes()

	if !Enum.BeamBufferHasIdentifier(buf) {
		t.Fatalf("buffer identifier = %q, want BEM1", buf[4:8])
	}
	if got := Enum.GetRootAsBeam(buf, 0).Ident(); got != Enum.BeamIdentifier {
		t.Fatalf("Beam.Ident = %v, want BeamIdentifier", got)
	}
}

// Tables ProbeIdentifier and ProbeFileIdentifier beside the root table Probe.
func TestBothNamesTaken(t *testing.T) {
	if Twice.ProbeFileIdentifier_ != "PRB1" {
		t.Fatalf("ProbeFileIdentifier_ = %q, want PRB1", Twice.ProbeFileIdentifier_)
	}

	b := flatbuffers.NewBuilder(0)
	name := b.CreateString("probe")
	Twice.ProbeFileIdentifierStart(b)
	Twice.ProbeFileIdentifierAddName(b, name)
	file := Twice.ProbeFileIdentifierEnd(b)
	Twice.ProbeStart(b)
	Twice.ProbeAddFile(b, file)
	Twice.FinishSizePrefixedProbeBuffer(b, Twice.ProbeEnd(b))
	buf := b.FinishedBytes()

	if !Twice.SizePrefixedProbeBufferHasIdentifier(buf) {
		t.Fatalf("buffer identifier = %q, want PRB1", buf[8:12])
	}
	var fileTable Twice.ProbeFileIdentifier
	if Twice.GetSizePrefixedRootAsProbe(buf, 0).File(&fileTable) == nil {
		t.Fatal("Probe.File is absent")
	}
	if got := string(fileTable.Name()); got != "probe" {
		t.Fatalf("ProbeFileIdentifier.Name = %q, want probe", got)
	}
}

// DockIdentifier is a table in another package, so Dock keeps DockIdentifier.
func TestNoCollisionKeepsTheName(t *testing.T) {
	if Plain.DockIdentifier != "DCK1" {
		t.Fatalf("DockIdentifier = %q, want DCK1", Plain.DockIdentifier)
	}

	b := flatbuffers.NewBuilder(0)
	Plain.DockStart(b)
	Plain.FinishDockBuffer(b, Plain.DockEnd(b))
	if !Plain.DockBufferHasIdentifier(b.FinishedBytes()) {
		t.Fatal("buffer identifier is not DCK1")
	}
}
