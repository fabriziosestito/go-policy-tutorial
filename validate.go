package main

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/tidwall/gjson"
)

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Access the **raw** JSON that describes the object
	podJSON := validationRequest.Request.Object

	// highlight-next-line
	// NOTE 1
	data := gjson.GetBytes(
		podJSON,
		"metadata.labels")

	var validationErr error
	labels := mapset.NewThreadUnsafeSet[string]()
	data.ForEach(func(key, value gjson.Result) bool {
		// highlight-next-line
		// NOTE 2
		label := key.String()
		labels.Add(label)

		// highlight-next-line
		// NOTE 3
		validationErr = validateLabel(label, value.String(), &settings)
		if validationErr != nil {
			return false
		}

		// keep iterating
		return true
	})

	// highlight-next-line
	// NOTE 4
	if validationErr != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(validationErr.Error()),
			kubewarden.NoCode)
	}

	// highlight-next-line
	// NOTE 5
	for requiredLabel := range settings.ConstrainedLabels {
		if !labels.Contains(requiredLabel) {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf("Constrained label %s not found inside of Pod", requiredLabel)),
				kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}

func validateLabel(label, value string, settings *Settings) error {
	if settings.DeniedLabels.Contains(label) {
		return fmt.Errorf("Label %s is on the deny list", label)
	}

	regExp, found := settings.ConstrainedLabels[label]
	if found {
		// This is a constrained label
		if !regExp.Match([]byte(value)) {
			return fmt.Errorf("The value of %s doesn't pass user-defined constraint", label)
		}
	}

	return nil
}
