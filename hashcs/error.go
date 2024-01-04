// hash1.  A tool to calculate the hash checksum of one local file.
// Copyright (C) 2023-2024  Yuan Gao
//
// This file is part of hash1.
//
// hash1 is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package hashcs

import "strconv"

// UnknownHashAlgorithmError is an error indicating that
// the specified hash algorithm is unknown.
type UnknownHashAlgorithmError struct {
	hashName string // The name of the unknown hash algorithm.
}

var _ error = (*UnknownHashAlgorithmError)(nil)

// NewUnknownHashAlgorithmError creates a new UnknownHashAlgorithmError
// with the specified hash algorithm name.
func NewUnknownHashAlgorithmError(hashName string) *UnknownHashAlgorithmError {
	return &UnknownHashAlgorithmError{hashName: hashName}
}

// HashName returns the hash algorithm name recorded in e.
//
// If e is nil, it returns "<nil>".
func (e *UnknownHashAlgorithmError) HashName() string {
	if e == nil {
		return "<nil>"
	}
	return e.hashName
}

// Error returns the error message.
//
// If e is nil, it returns "<nil *UnknownHashAlgorithmError>".
func (e *UnknownHashAlgorithmError) Error() string {
	if e == nil {
		return "<nil *UnknownHashAlgorithmError>"
	}
	return "the hash algorithm " + strconv.Quote(e.hashName) + " is unknown"
}
