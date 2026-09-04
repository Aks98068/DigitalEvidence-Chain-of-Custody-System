package service

import (
	"fmt"
	"os"
	"time"

	"forensix-backend/internal/models"

	"github.com/jung-kurt/gofpdf"
)

func (s *CaseService) GenerateCaseReportPDF(caseID int) (string, error) {
	report, err := s.GenerateCaseReport(caseID)
	if err != nil {
		return "", err
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Forensic Investigation Report")
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Case Details")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	cases, _ := report["case"].(*models.InvestigationCase)
	if cases != nil {
		pdf.Cell(40, 6, fmt.Sprintf("Case ID: %s", cases.CaseID))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("Title: %s", cases.Title))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("Status: %s", cases.Status))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("Priority: %s", cases.Priority))
		pdf.Ln(6)
		if cases.Description != nil {
			pdf.Cell(40, 6, fmt.Sprintf("Description: %s", *cases.Description))
			pdf.Ln(6)
		}
	}

	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Evidence")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	evidenceList, _ := report["evidence"].([]*models.Evidence)
	if len(evidenceList) > 0 {
		for _, e := range evidenceList {
			pdf.Cell(40, 6, fmt.Sprintf("- %s (%s)", e.FileName, e.Category))
			pdf.Ln(6)
		}
	} else {
		pdf.Cell(40, 6, "No evidence uploaded")
		pdf.Ln(6)
	}

	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Timeline")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	timeline, _ := report["timeline"].([]*models.InvestigationTimeline)
	if len(timeline) > 0 {
		for _, t := range timeline {
			pdf.Cell(40, 6, fmt.Sprintf("[%s] %s", t.CreatedAt.Format(time.RFC3339), t.Description))
			pdf.Ln(6)
		}
	} else {
		pdf.Cell(40, 6, "No timeline events")
		pdf.Ln(6)
	}

	filePath := fmt.Sprintf("./reports/case_%d_%d.pdf", caseID, time.Now().Unix())
	os.MkdirAll("./reports", 0755)
	if err := pdf.OutputFileAndClose(filePath); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *EvidenceService) GenerateEvidenceIntegrityReportPDF(evidenceID int) (string, error) {
	report, err := s.GenerateEvidenceIntegrityReport(evidenceID)
	if err != nil {
		return "", err
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Evidence Integrity Report")
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Evidence Details")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	evidence, _ := report["evidence"].(*models.Evidence)
	if evidence != nil {
		pdf.Cell(40, 6, fmt.Sprintf("Evidence ID: %s", evidence.EvidenceID))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("File: %s", evidence.FileName))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("Category: %s", evidence.Category))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("SHA256: %s", evidence.SHA256Hash))
		pdf.Ln(6)
	}

	integrityValid, _ := report["integrity_valid"].(bool)
	pdf.Cell(40, 6, fmt.Sprintf("Integrity Valid: %v", integrityValid))
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Chain of Custody")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	custodyRecords, _ := report["chain_of_custody"].([]*models.ChainOfCustody)
	if len(custodyRecords) > 0 {
		for _, c := range custodyRecords {
			pdf.Cell(40, 6, fmt.Sprintf("[%s] %s by User %d", c.CreatedAt.Format(time.RFC3339), c.Action, c.UserID))
			pdf.Ln(6)
		}
	} else {
		pdf.Cell(40, 6, "No custody records")
		pdf.Ln(6)
	}

	filePath := fmt.Sprintf("./reports/evidence_%d_%d.pdf", evidenceID, time.Now().Unix())
	os.MkdirAll("./reports", 0755)
	if err := pdf.OutputFileAndClose(filePath); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *EvidenceService) GenerateChainOfCustodyReportPDF(evidenceID int) (string, error) {
	records, err := s.GetChainOfCustody(evidenceID)
	if err != nil {
		return "", err
	}

	evidence, _ := s.evidenceRepo.FindByID(evidenceID)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Chain of Custody Report")
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Evidence")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	if evidence != nil {
		pdf.Cell(40, 6, fmt.Sprintf("Evidence ID: %s", evidence.EvidenceID))
		pdf.Ln(6)
		pdf.Cell(40, 6, fmt.Sprintf("File: %s", evidence.FileName))
		pdf.Ln(6)
	}

	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Custody Records")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	for _, c := range records {
		pdf.Cell(40, 6, fmt.Sprintf("[%s] %s by User %d", c.CreatedAt.Format(time.RFC3339), c.Action, c.UserID))
		pdf.Ln(6)
		if c.Notes != nil {
			pdf.Cell(40, 6, fmt.Sprintf("Notes: %s", *c.Notes))
			pdf.Ln(6)
		}
	}

	filePath := fmt.Sprintf("./reports/custody_%d_%d.pdf", evidenceID, time.Now().Unix())
	os.MkdirAll("./reports", 0755)
	if err := pdf.OutputFileAndClose(filePath); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *UserService) GenerateAuditLogReportPDF(searchTerm string, limit int) (string, error) {
	logs, err := s.SearchAuditLogs(searchTerm, limit, 0)
	if err != nil {
		return "", err
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Audit Log Report")
	pdf.Ln(12)

	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(30, 8, "ID")
	pdf.Cell(30, 8, "User")
	pdf.Cell(40, 8, "Action")
	pdf.Cell(30, 8, "Module")
	pdf.Cell(40, 8, "Date")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)

	for _, l := range logs {
		userID := ""
		if l.UserID != nil {
			userID = fmt.Sprintf("%d", *l.UserID)
		}
		module := ""
		if l.Module != nil {
			module = *l.Module
		}
		pdf.Cell(30, 6, fmt.Sprintf("%d", l.ID))
		pdf.Cell(30, 6, userID)
		pdf.Cell(40, 6, l.Action)
		pdf.Cell(30, 6, module)
		pdf.Cell(40, 6, l.CreatedAt.Format(time.RFC3339))
		pdf.Ln(6)
	}

	filePath := fmt.Sprintf("./reports/audit_%d.pdf", time.Now().Unix())
	os.MkdirAll("./reports", 0755)
	if err := pdf.OutputFileAndClose(filePath); err != nil {
		return "", err
	}
	return filePath, nil
}
