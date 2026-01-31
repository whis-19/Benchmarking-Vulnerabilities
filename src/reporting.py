import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class SecurityReporter:
    def __init__(self, benchmark_csv="benchmark_results.csv", output_pdf="security_report.pdf"):
        self.benchmark_csv = benchmark_csv
        self.output_pdf = output_pdf
        self.styles = getSampleStyleSheet()
        self.bandit_json = os.path.join("bandit_output", "all_pipelines.json")
        self.semgrep_json = os.path.join("sem_grep_output", "all_pipelines.json")

    def create_charts(self, df):
        # Calculate Averages
        avg_df = df.groupby('Approach').agg({
            'Latency': 'mean',
            'Weaknesses': 'mean',
            'Density': 'mean'
        }).reset_index()

        plt.figure(figsize=(10, 5))
        
        # Latency Chart
        plt.subplot(1, 2, 1)
        plt.bar(avg_df['Approach'], avg_df['Latency'], color=['#3498db', '#e74c3c', '#2ecc71', '#f1c40f'])
        plt.title('Average Latency (s)')
        plt.ylabel('Seconds')

        # Density Chart
        plt.subplot(1, 2, 2)
        plt.bar(avg_df['Approach'], avg_df['Density'], color=['#3498db', '#e74c3c', '#2ecc71', '#f1c40f'])
        plt.title('Average Weakness Density')
        plt.ylabel('Density (%)')

        plt.tight_layout()
        chart_path = "comparison_charts.png"
        plt.savefig(chart_path)
        plt.close()
        return chart_path

    def get_security_summary(self):
        summary = []
        
        # Bandit Summary
        if os.path.exists(self.bandit_json):
            with open(self.bandit_json, 'r') as f:
                data = json.load(f)
                issues = data.get('results', [])
                bandit_count = len(issues)
                top_issues = {}
                for issue in issues:
                    test_id = issue.get('test_id', 'Unknown')
                    top_issues[test_id] = top_issues.get(test_id, 0) + 1
                
                summary.append(f"<b>Bandit Analysis:</b> Detected {bandit_count} total issues.")
                sorted_issues = sorted(top_issues.items(), key=lambda x: x[1], reverse=True)[:3]
                for issue_id, count in sorted_issues:
                    summary.append(f"- {issue_id}: {count} occurrences")

        # Semgrep Summary
        if os.path.exists(self.semgrep_json):
            with open(self.semgrep_json, 'r') as f:
                data = json.load(f)
                issues = data.get('results', [])
                semgrep_count = len(issues)
                summary.append(f"<br/><b>Semgrep Analysis:</b> Detected {semgrep_count} total issues.")
        
        return "<br/>".join(summary) if summary else "No detailed scanner data available."

    def generate_report(self):
        if not os.path.exists(self.benchmark_csv):
            print(f"Error: {self.benchmark_csv} not found.")
            return

        df = pd.read_csv(self.benchmark_csv)
        chart_path = self.create_charts(df)
        
        doc = SimpleDocTemplate(self.output_pdf, pagesize=letter)
        elements = []

        # Title
        title_style = ParagraphStyle('CustomTitle', parent=self.styles['Title'], fontSize=24, spaceAfter=20)
        elements.append(Paragraph("Security Evaluation Report", title_style))
        
        header_style = ParagraphStyle('Header', parent=self.styles['Normal'], fontSize=10, textColor=colors.grey)
        elements.append(Paragraph("Automated Benchmarking of LLM Code Generation Techniques", header_style))
        elements.append(Spacer(1, 0.5 * inch))

        # Executive Summary
        elements.append(Paragraph("1. Performance Visualization", self.styles['Heading2']))
        elements.append(Spacer(1, 12))
        elements.append(Image(chart_path, width=6*inch, height=3*inch))
        elements.append(Spacer(1, 0.2 * inch))

        # Benchmark Table
        elements.append(Paragraph("2. Detailed Benchmark Data", self.styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        # Clean up table data
        display_df = df[['Task', 'Approach', 'Latency', 'Weaknesses', 'Density']].copy()
        display_df['Latency'] = display_df['Latency'].round(2)
        display_df['Density'] = display_df['Density'].map(lambda x: f"{x*100:.2f}%")
        
        table_data = [display_df.columns.values.tolist()] + display_df.values.tolist()
        table = Table(table_data, colWidths=[0.8*inch, 1.2*inch, 1*inch, 1*inch, 1.5*inch])
        
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#ecf0f1")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f9f9f9")])
        ]))
        
        elements.append(table)
        elements.append(PageBreak())

        # Scanner Analysis
        elements.append(Paragraph("3. Aggregated Scanner Findings", self.styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        summary_text = self.get_security_summary()
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph("<i>Note: Individual findings are stored as JSON artifacts in the project directory.</i>", self.styles['Italic']))

        doc.build(elements)
        print(f"Professional PDF report generated: {self.output_pdf}")

def generate_pdf_report():
    reporter = SecurityReporter()
    reporter.generate_report()
