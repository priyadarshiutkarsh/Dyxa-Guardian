# gradio_interface.py
import gradio as gr
import pandas as pd
from security_analyzer import CodeSecurityAnalyzer, CodeMetrics, SecurityIssue
import plotly.express as px
import plotly.graph_objects as go
import asyncio

def sync_analyze_wrapper(input_code, language):
    try:
        vulnerability_chart, metrics_chart, issues = asyncio.run(analyze_code(input_code, language))
        issues_df = pd.DataFrame(issues)
        return vulnerability_chart, metrics_chart, issues_df
    except Exception as e:
        logger.error(f"Error during analysis: {e}", exc_info=True)
        error_vulnerability_chart = px.bar(title=f"Analysis Error: {str(e)}", x=['Error'], y=[1])
        error_metrics_chart = go.Figure(data=[go.Bar(x=['Error'], y=[0])], layout={'title': 'Metrics Analysis Failed'})
        error_issues_df = pd.DataFrame([{
            'Severity': 'Critical',
            'Description': str(e),
            'Line Number': 0,
            'Suggestion': 'Check code and try again',
            'Code Snippet': '',
            'CWE ID': 'N/A',
            'OWASP Category': 'N/A'
        }])
        return error_vulnerability_chart, error_metrics_chart, error_issues_df

def create_gradio_interface():
    with gr.Blocks(theme=gr.themes.Default()) as app:
        gr.Markdown(
            """
            <h1 style='text-align: center; color: #4CAF50; font-family: "Arial", sans-serif;'>
                Dyxa Guardian
            </h1>
            <p style='text-align: center; color: #666; font-family: "Arial", sans-serif;'>
                Code Security Analyzer
            </p>
            """
        )

        # Interactive Code Editor
        input_code = gr.Textbox(
            label="Input Code",
            placeholder="Paste your code here...",
            lines=15,
            elem_classes="monaco-editor"
        )
        language = gr.Dropdown(
            choices=["python", "javascript", "java"],
            label="Language",
            value="python",
            elem_classes="dropdown"
        )

        # Analyze Button
        analyze_button = gr.Button(
            "Analyze Code",
            variant="primary",
            elem_classes="analyze-button"
        )

        # Export Report Buttons
        with gr.Row():
            export_json = gr.Button(
                "Export as JSON",
                elem_classes="export-button"
            )
            export_csv = gr.Button(
                "Export as CSV",
                elem_classes="export-button"
            )
            export_pdf = gr.Button(
                "Export as PDF",
                elem_classes="export-button"
            )

        # Dashboard
        with gr.Row():
            vulnerability_chart = gr.Plot(
                label="Vulnerability Distribution",
                elem_classes="chart"
            )
            metrics_chart = gr.Plot(
                label="Code Metrics",
                elem_classes="chart"
            )

        # Issue Details Table
        issue_details = gr.DataFrame(
            headers=["Severity", "Description", "Line Number", "Suggestion", "Code Snippet", "CWE ID", "OWASP Category"],
            type="pandas",
            elem_classes="dataframe"
        )

        # File Download Component
        file_download = gr.File(
            label="Download Report",
            elem_classes="file-download"
        )

        # Analyze Button Logic
        analyze_button.click(
            fn=lambda code, lang: sync_analyze_wrapper(code, lang),
            inputs=[input_code, language],
            outputs=[vulnerability_chart, metrics_chart, issue_details]
        )

        # Export Report Logic
        export_json.click(
            fn=lambda issues_df: export_report(issues_df, format="json"),
            inputs=issue_details,
            outputs=file_download
        )
        export_csv.click(
            fn=lambda issues_df: export_report(issues_df, format="csv"),
            inputs=issue_details,
            outputs=file_download
        )
        export_pdf.click(
            fn=lambda issues_df: export_report(issues_df, format="pdf"),
            inputs=issue_details,
            outputs=file_download
        )

    return app

custom_css = """
.monaco-editor {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px;
    background-color: #f9f9f9;
    color: #333;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 15px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    transition: background-color 0.3s ease, color 0.3s ease;
}

.dropdown {
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    border-radius: 8px;
    padding: 8px;
    border: 1px solid #ddd;
    background-color: #fff;
    transition: background-color 0.3s ease, color 0.3s ease;
}

.analyze-button {
    font-family: 'Arial', sans-serif;
    font-size: 16px;
    font-weight: bold;
    background-color: #4CAF50;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px 24px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.analyze-button:hover {
    background-color: #45a049;
}

.export-button {
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    background-color: white;
    color: #4CAF50;
    border: 1px solid #4CAF50;
    border-radius: 8px;
    padding: 8px 16px;
    cursor: pointer;
    transition: background-color 0.3s ease, color 0.3s ease;
}

.export-button:hover {
    background-color: #4CAF50;
    color: white;
}

.chart {
    border-radius: 8px;
    border: 1px solid #ddd;
    padding: 15px;
    background-color: #fff;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    transition: background-color 0.3s ease, color 0.3s ease;
}

.dataframe {
    border-radius: 8px;
    border: 1px solid #ddd;
    padding: 15px;
    background-color: #fff;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    transition: background-color 0.3s ease, color 0.3s ease;
}

.file-download {
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    border-radius: 8px;
    border: 1px solid #ddd;
    padding: 8px;
    background-color: #fff;
    transition: background-color 0.3s ease, color 0.3s ease;
}

.theme-switcher {
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    border-radius: 8px;
    padding: 8px;
    border: 1px solid #ddd;
    background-color: #fff;
    transition: background-color 0.3s ease, color 0.3s ease;
}

/* Dark Theme */
.dark .monaco-editor {
    background-color: #333;
    color: #f9f9f9;
    border-color: #555;
}

.dark .dropdown {
    background-color: #444;
    color: #f9f9f9;
    border-color: #555;
}

.dark .analyze-button {
    background-color: #45a049;
}

.dark .export-button {
    background-color: #444;
    color: #4CAF50;
    border-color: #4CAF50;
}

.dark .export-button:hover {
    background-color: #4CAF50;
    color: white;
}

.dark .chart {
    background-color: #444;
    color: #f9f9f9;
    border-color: #555;
}

.dark .dataframe {
    background-color: #444;
    color: #f9f9f9;
    border-color: #555;
}

.dark .file-download {
    background-color: #444;
    color: #f9f9f9;
    border-color: #555;
}

.dark .theme-switcher {
    background-color: #444;
    color: #f9f9f9;
    border-color: #555;
}
"""

def inject_custom_css():
    from IPython.display import HTML
    display(HTML(f"<style>{custom_css}</style>"))

inject_custom_css()

# Launch the Gradio app
app = create_gradio_interface()
app.launch(debug=False, share=True)
