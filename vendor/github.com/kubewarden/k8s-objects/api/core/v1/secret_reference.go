// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// SecretReference SecretReference represents a Secret Reference. It has enough information to retrieve secret in any namespace
//
// swagger:model SecretReference
type SecretReference struct {

	// name is unique within a namespace to reference a secret resource.
	Name string `json:"name,omitempty"`

	// namespace defines the space within which the secret name must be unique.
	Namespace string `json:"namespace,omitempty"`
}