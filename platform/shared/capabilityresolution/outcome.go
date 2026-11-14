// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capabilityresolution

const (
	// PaymentExceptionModuleID and SupportRefundModuleID are independent
	// commercial grants. Neither module implies the other.
	PaymentExceptionModuleID = "payment_exception"
	SupportRefundModuleID    = "support_refund"

	// Workflow capabilities admit one case operation through the corresponding
	// Enterprise module. They are authority vocabulary, not caller input.
	PaymentExceptionWorkflowCapabilityID = "payment_exception.workflow"
	SupportRefundWorkflowCapabilityID    = "support_refund.workflow"

	// Case limits are durable monthly usage dimensions. Each module has a
	// distinct counter so purchasing one allowance cannot spend or unlock the
	// other module's allowance.
	PaymentExceptionCasesLimitID = "payment_exception.cases"
	SupportRefundCasesLimitID    = "support_refund.cases"
)
