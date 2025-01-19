from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor

# Initialize the presentation
prs = Presentation()

# Slide 1: Title Slide
slide = prs.slides.add_slide(prs.slide_layouts[0])
title = slide.shapes.title
subtitle = slide.placeholders[1]

title.text = "Network LAN Device Map and Investigation Tool"
subtitle.text = "HWNN De Silva\nB.Sc. (Hons) Computer Networks\nSupervisor: Mr. Chamara Disanayake"

# Slide 2: Background of the Study
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Background of the Study"
content.text = ("- Importance of efficient LAN mapping in IT environments\n"
                "- Challenges in manual network mapping\n"
                "- Need for automated, accurate, and real-time network visualization tools")

# Slide 3: Research Problem / Research Question
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Research Problem / Research Question"
content.text = ("- Problem: Manual network mapping is error-prone and time-consuming\n"
                "- Objective: Develop an automated tool for LAN mapping and visualization\n"
                "- Research Question: How can a command-line LAN mapping tool improve network management?")

# Slide 4: Findings from Literature Review
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Findings from Literature Review"
content.text = ("- Limitations of current LAN mapping tools\n"
                "- Existing solutions: Nmap, SolarWinds, Spiceworks\n"
                "- Research gap: Need for a scalable, affordable, and automated tool for small to medium networks")

# Slide 5: Research Methodology
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Research Methodology"
content.text = ("- Approach: Deductive and positivist paradigm\n"
                "- Strategy: Experimental approach to test tool effectiveness\n"
                "- Design Methodology: Object-Oriented Analysis and Design (OOAD)")

# Slide 6: Research Methods
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Research Methods"
content.text = ("- Data collection: Expert opinions, performance metrics\n"
                "- Test subjects: Network administrators and IT professionals for feedback")

# Slide 7: Data Analysis
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Data Analysis"
content.text = ("- Quantitative metrics: Accuracy, scalability, and performance tests\n"
                "- Qualitative insights: Usability feedback from experts")

# Slide 8: System Design
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "System Design"
content.text = ("- Key Components:\n"
                "   - Network Scanner (Nmap-based)\n"
                "   - Visualization (NetworkX and Matplotlib)\n"
                "   - Report Generator (python-docx)\n"
                "- System Architecture Diagram")

# Slide 9: Implementation Overview
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Implementation Overview"
content.text = ("- Technologies: Python, Nmap, NetworkX, Matplotlib, python-docx\n"
                "- Code modules: Network discovery, data parsing, visualization, reporting")

# Slide 10: Results – Functional Testing
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Results – Functional Testing"
content.text = ("- Accuracy: Achieved 95% detection rate\n"
                "- Performance: Quick response times for small to medium networks\n"
                "- Scalability: Efficient handling up to 256 devices in /24 subnet")

# Slide 11: Results – Non-functional Testing
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Results – Non-functional Testing"
content.text = ("- Performance: Completed scans within expected timeframes\n"
                "- Usability: Positive feedback on simplicity and efficiency from network administrators")

# Slide 12: System Demonstration (Optional)
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "System Demonstration (Optional)"
content.text = "Prototype / Live Demo: System interface, key functions, and sample network visualization"

# Slide 13: Discussion
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Discussion"
content.text = ("- Benefits of the tool: Simplifies LAN management for small to medium networks\n"
                "- Key insights from testing: Reliable device detection, efficient visualization, user-friendly interface")

# Slide 14: Conclusion and Future Work
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Conclusion and Future Work"
content.text = ("- Conclusion: Automated LAN mapping tool improves network management efficiency\n"
                "- Future work: GUI development, real-time monitoring, protocol support")

# Slide 15: Acknowledgments and Q&A
slide = prs.slides.add_slide(prs.slide_layouts[1])
title, content = slide.shapes.title, slide.placeholders[1]
title.text = "Acknowledgments and Q&A"
content.text = ("Thanking supervisor, family, and friends for their support.\n"
                "Open floor for questions.")

# Save the presentation
pptx_path = "/mnt/data/Final_Year_Research_Project_Presentation.pptx"
prs.save(pptx_path)
pptx_path
