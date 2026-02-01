# LaTeX Report Compilation Guide

## Overview

The file `pipeline_report.tex` contains a comprehensive research report documenting the three proposed superior code generation pipelines.

## Report Contents

### Sections

1. **Abstract** - Summary of contributions and expected results
2. **Introduction** - Motivation and contributions
3. **Background and Related Work** - Existing approaches and their limitations
4. **Proposed Pipelines** - Detailed description of CAG+RCI, CAG+RAG, and RAG+CAG+RCI
5. **Implementation Details** - Core components and algorithms
6. **Expected Results and Analysis** - Performance comparison and improvements
7. **Use Case Recommendations** - When to use each pipeline
8. **Conclusion and Future Work** - Summary and potential extensions

### Key Features

- ✅ **3 Algorithms**: Context Analysis, Guideline Fusion, Adaptive Refinement
- ✅ **3 Comparison Tables**: Existing performance, new performance, feature matrix
- ✅ **Mathematical Formulations**: Pipeline equations and improvement calculations
- ✅ **Professional Formatting**: IEEE-style academic paper

## Compilation Instructions

### Prerequisites

Install a LaTeX distribution:

**Windows**:
```bash
# Download and install MiKTeX from https://miktex.org/download
# Or use Chocolatey:
choco install miktex
```

**Linux**:
```bash
sudo apt-get install texlive-full
```

**macOS**:
```bash
brew install --cask mactex
```

### Compile the Report

#### Method 1: Command Line

```bash
cd c:\Users\Whis\Downloads\scripts\scripts

# Compile (run twice for references)
pdflatex pipeline_report.tex
pdflatex pipeline_report.tex

# Clean up auxiliary files (optional)
del pipeline_report.aux pipeline_report.log pipeline_report.out
```

#### Method 2: Using latexmk (Recommended)

```bash
# Install latexmk if not already installed
# Then run:
latexmk -pdf pipeline_report.tex

# Clean up
latexmk -c
```

#### Method 3: Online (Overleaf)

1. Go to https://www.overleaf.com
2. Create a new project
3. Upload `pipeline_report.tex`
4. Click "Recompile"

### Output

The compilation will generate:
- **`pipeline_report.pdf`** - The final research report

## Report Highlights

### Expected Performance Improvements

| Metric | Best Existing (RCI+RAG) | Our Best (RAG+CAG+RCI) | Improvement |
|--------|------------------------|------------------------|-------------|
| Security Score | 82% | **95%+** | **+13%** |
| Syntax Errors | 6% | **<1%** | **-5%** |
| High-Severity Issues | 18% | **<5%** | **-13%** |
| Code Quality | 78% | **92%+** | **+14%** |

### Key Innovations Documented

1. **Context-Aware Generation (CAG)**
   - Automatic security domain detection
   - CWE category identification
   - Domain-specific guideline selection

2. **Guideline Fusion**
   - Merges context-specific and RAG-retrieved guidelines
   - Deduplication algorithm
   - Comprehensive security coverage

3. **Adaptive Refinement**
   - Only refines when security score < 80
   - Convergence detection
   - Targeted critique based on detected issues

4. **Comprehensive Validation**
   - Syntax validation
   - AST parsing
   - Security scanning (Bandit integration)
   - Quality metrics

## Customization

### Change Paper Size

Edit line 2:
```latex
\documentclass[11pt,a4paper]{article}  % Current: A4
\documentclass[11pt,letterpaper]{article}  % Change to: Letter
```

### Change Font Size

Edit line 2:
```latex
\documentclass[11pt,a4paper]{article}  % Current: 11pt
\documentclass[12pt,a4paper]{article}  % Change to: 12pt
```

### Add Authors

Edit the `\author{}` command around line 55:
```latex
\author{Your Name \\ Your Institution \\ your.email@example.com}
```

### Modify Tables

All tables are in standard LaTeX format. Edit the data in the `tabular` environments.

### Add Figures

To add figures (e.g., pipeline diagrams):
```latex
\begin{figure}[h]
\centering
\includegraphics[width=0.8\textwidth]{pipeline_diagram.png}
\caption{Pipeline Architecture}
\label{fig:pipeline}
\end{figure}
```

## Troubleshooting

### Missing Packages

If you get errors about missing packages:

**MiKTeX (Windows)**:
- MiKTeX will automatically prompt to install missing packages
- Or manually install: `mpm --install <package-name>`

**TeX Live (Linux/Mac)**:
```bash
sudo tlmgr install <package-name>
```

### Common Packages Used

- `inputenc` - UTF-8 encoding
- `geometry` - Page margins
- `graphicx` - Images
- `amsmath`, `amssymb` - Math symbols
- `booktabs` - Professional tables
- `algorithm`, `algorithmic` - Algorithms
- `tikz` - Diagrams
- `hyperref` - Hyperlinks

### Compilation Errors

If you get errors:
1. Check the `.log` file for details
2. Ensure all packages are installed
3. Run `pdflatex` twice (for references)
4. Try `latexmk -pdf` for automatic handling

## Quick Reference

### File Structure

```
scripts/
├── pipeline_report.tex       # Main LaTeX source
├── pipeline_report.pdf       # Generated PDF (after compilation)
├── pipeline_report.aux       # Auxiliary file (can delete)
├── pipeline_report.log       # Log file (can delete)
└── pipeline_report.out       # Hyperref output (can delete)
```

### Compilation Commands

```bash
# Basic compilation
pdflatex pipeline_report.tex

# With latexmk (automatic)
latexmk -pdf pipeline_report.tex

# Clean auxiliary files
latexmk -c

# Clean everything including PDF
latexmk -C
```

## Summary

The LaTeX report provides:

✅ **Comprehensive documentation** of all three pipelines  
✅ **Mathematical formulations** of pipeline architectures  
✅ **Performance comparisons** with existing approaches  
✅ **Implementation details** with algorithms  
✅ **Professional formatting** suitable for academic publication

**Compile with**: `pdflatex pipeline_report.tex` (run twice)

The resulting PDF is a complete research report suitable for:
- Academic submission
- Technical documentation
- Project presentations
- Research proposals
