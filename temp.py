from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.enums import TA_JUSTIFY


def create_pdf(filename, text):
    doc = SimpleDocTemplate(filename, pagesize=A4)

    # Define a custom style with justified alignment
    styles = getSampleStyleSheet()
    justified_style = ParagraphStyle(
        'Justify',
        parent=styles['Normal'],
        fontName="Times-Roman",
        fontSize=12,
        leading=16,  # Line spacing
        alignment=TA_JUSTIFY  # Justify the text
    )

    # Create a Paragraph to handle long text with automatic line breaks and justification
    content = Paragraph(text, justified_style)

    # Build PDF
    doc.build([content])
    print(f"PDF '{filename}' created successfully with justified text.")


# Sample large content
large_text = """This is a long text that will automatically wrap onto the next line when it reaches the end of the page. 
This ensures that the text does not overflow and continues onto the next lines properly. 
By setting the alignment to 'justify', the text will be evenly distributed across the width of the page. 
This improves readability and makes the document look more professional."""

create_pdf("output.pdf", large_text)