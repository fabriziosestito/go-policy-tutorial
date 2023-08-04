package main

import (
	"encoding/json"
	"fmt"

	onelog "github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func validate(payload []byte) ([]byte, error) {
	// highlight-next-line
	// NOTE 1
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// highlight-next-line
	// NOTE 2
	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// highlight-next-line
	// NOTE 3
	// Access the **raw** JSON that describes the object
	podJSON := validationRequest.Request.Object

	// highlight-next-line
	// NOTE 4
	// Try to create a Pod instance using the RAW JSON we got from the
	// ValidationRequest.
	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(podJSON), pod); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("Cannot decode Pod object: %s", err.Error())),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		e.String("name", pod.Metadata.Name)
		e.String("namespace", pod.Metadata.Namespace)
	})

	// highlight-next-line
	// NOTE 5
	for label, value := range pod.Metadata.Labels {
		if err := validateLabel(label, value, &settings); err != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(err.Error()),
				kubewarden.NoCode)
		}
	}

	for requiredLabel := range settings.ConstrainedLabels {
		_, found := pod.Metadata.Labels[requiredLabel]
		if !found {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf(
					"Constrained label %s not found inside of Pod", requiredLabel),
				),
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
