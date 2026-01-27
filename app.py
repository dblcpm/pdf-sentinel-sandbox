"""
PDF Sentinel - Streamlit Application
Forensic PDF Analysis Tool for detecting prompt injection and malicious content
"""

import streamlit as st
import os
import tempfile
from pathlib import Path
from analyzer import PDFAnalyzer


# Check if semantic detection should be enabled
ENABLE_SEMANTIC = os.getenv('ENABLE_SEMANTIC_DETECTION', 'true').lower() in ('true', '1', 'yes')


# Map technical YARA tags to human-readable explanations
YARA_EXPLANATIONS = {
    "/AA": {
        "title": "⚠️ Automatic Action Trigger",
        "desc": "The '/AA' tag stands for 'Additional Actions'. It allows the PDF to execute commands automatically when you interact with a page (like scrolling or hovering). Malware often uses this to run code without your explicit consent."
    },
    "/OpenAction": {
        "title": "🚨 Auto-Execute on Open",
        "desc": "The '/OpenAction' command triggers an action immediately when the document is opened. This is a high-risk feature often used by malware to launch attacks instantly before you can react."
    },
    "/JS": {
        "title": "📜 JavaScript Embedded",
        "desc": "The '/JS' tag indicates raw JavaScript code is hidden inside the file structure. While sometimes used for legitimate forms, it is the most common vehicle for malicious PDF payloads."
    },
    "/JavaScript": {
        "title": "📜 JavaScript Action",
        "desc": "This specific tag triggers a script. If you didn't expect this document to contain code, this is highly suspicious."
    },
    "/Launch": {
        "title": "🚀 Program Launcher",
        "desc": "The '/Launch' command attempts to open an external program or file on your computer (like cmd.exe or PowerShell). This is extremely dangerous."
    },
    "ignore previous": {
        "title": "🧠 AI Prompt Injection",
        "desc": "The phrase 'ignore previous instructions' is a classic attempt to hijack an AI system. It tries to force the AI to disregard safety rules and execute unauthorized commands."
    },
    "system prompt": {
        "title": "🧠 System Prompt Leak",
        "desc": "References to 'system prompt' often indicate an attempt to trick the AI into revealing its internal configuration or secrets."
    }
}


def main():
    """Main Streamlit application"""
    
    # Page configuration
    st.set_page_config(
        page_title="PDF Sentinel",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Title and description
    st.title("🔍 PDF Sentinel")
    st.markdown("""
    **Forensic PDF Analysis Tool**  
    Detect prompt injection, invisible text, and malicious content in PDF files.
    """)
    
    # Sidebar
    with st.sidebar:
        st.header("About")
        st.info("""
        PDF Sentinel analyzes PDF files for:
        - 🔎 Invisible text patterns
        - 🎯 Suspicious keywords (YARA)
        - 🧠 Semantic prompt injection
        - 🛡️ Hidden commands
        """)
        
        if not ENABLE_SEMANTIC:
            st.warning("""
            ⚠️ **Semantic Detection Disabled**  
            Set ENABLE_SEMANTIC_DETECTION=true to enable
            """)
        
        st.header("Settings")
        semantic_threshold = st.slider(
            "Semantic Detection Threshold",
            min_value=0.5,
            max_value=0.95,
            value=0.7,
            step=0.05,
            help="Higher values = stricter detection",
            disabled=not ENABLE_SEMANTIC
        )
        
        show_technical = st.checkbox(
            "Show Technical Details",
            value=False,
            help="Display detailed technical analysis"
        )
    
    # File uploader
    st.header("Upload PDF File")
    uploaded_file = st.file_uploader(
        "Choose a PDF file to analyze",
        type=['pdf'],
        help="Upload a PDF file for forensic analysis"
    )
    
    if uploaded_file is not None:
        # Display file info
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Filename", uploaded_file.name)
        with col2:
            st.metric("Size", f"{uploaded_file.size / 1024:.2f} KB")
        with col3:
            file_type = uploaded_file.type
            st.metric("Type", file_type)
        
        # Analyze button
        if st.button("🔍 Analyze PDF", type="primary"):
            analyze_pdf_file(uploaded_file, semantic_threshold, show_technical)


def analyze_pdf_file(uploaded_file, semantic_threshold: float, show_technical: bool):
    """
    Analyze the uploaded PDF file
    
    Args:
        uploaded_file: Streamlit uploaded file object
        semantic_threshold: Threshold for semantic detection
        show_technical: Whether to show technical details
    """
    # Create temporary file for analysis
    temp_dir = None
    try:
        with st.spinner("🔄 Analyzing PDF..."):
            # Create secure temporary directory
            temp_dir = tempfile.mkdtemp(prefix='pdf_sentinel_upload_')
            temp_pdf_path = os.path.join(temp_dir, uploaded_file.name)
            
            # Save uploaded file
            with open(temp_pdf_path, 'wb') as f:
                f.write(uploaded_file.getbuffer())
            
            # Initialize analyzer
            analyzer = PDFAnalyzer(yara_rules_path="signatures.yara", enable_semantic=ENABLE_SEMANTIC)
            
            # Perform analysis
            results = analyzer.analyze_pdf(temp_pdf_path)
            
            # Calculate risk score
            risk_level, risk_score = analyzer.get_risk_score(results)
            
            # Display results
            display_results(results, risk_level, risk_score, show_technical, semantic_threshold)
    
    except Exception as e:
        st.error(f"❌ Error during analysis: {str(e)}")
    
    finally:
        # Clean up temporary files
        if temp_dir and os.path.exists(temp_dir):
            import shutil
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                st.warning(f"Could not clean up temporary files: {str(e)}")


def display_results(results: dict, risk_level: str, risk_score: int, 
                   show_technical: bool, semantic_threshold: float):
    """
    Display analysis results
    
    Args:
        results: Analysis results dictionary
        risk_level: Risk level string
        risk_score: Risk score (0-100)
        show_technical: Whether to show technical details
        semantic_threshold: Semantic detection threshold used
    """
    st.header("📊 Analysis Results")
    
    # Risk score display
    st.subheader("Risk Assessment")
    
    # Color code based on risk level
    risk_colors = {
        "CLEAN": "green",
        "LOW": "blue",
        "MEDIUM": "orange",
        "HIGH": "red",
        "CRITICAL": "darkred"
    }
    
    color = risk_colors.get(risk_level, "gray")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"### Risk Level: :{color}[{risk_level}]")
    with col2:
        st.markdown(f"### Risk Score: {risk_score}/100")
    
    # Progress bar for risk score
    st.progress(risk_score / 100)
    
    # Display errors if any
    if results.get('errors'):
        st.error("⚠️ Analysis Errors:")
        for error in results['errors']:
            st.write(f"- {error}")
    
    # Tabs for different detection types
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Invisible Text",
        "🎯 YARA Matches",
        "🧠 Semantic Detection",
        "🔒 Privacy",
        "📋 Summary"
    ])
    
    with tab1:
        display_invisible_text_results(results, show_technical)
    
    with tab2:
        display_yara_results(results, show_technical)
    
    with tab3:
        display_semantic_results(results, show_technical, semantic_threshold)
    
    with tab4:
        display_privacy_results(results, show_technical)
    
    with tab5:
        display_summary(results, risk_level, risk_score)


def display_invisible_text_results(results: dict, show_technical: bool):
    """Display invisible text detection results"""
    st.subheader("Invisible Text Detection")
    
    invisible_text = results.get('invisible_text', [])
    
    if not invisible_text:
        st.success("✅ No invisible text detected")
    else:
        st.warning(f"⚠️ Found {len(invisible_text)} instance(s) of invisible text")
        
        for i, detection in enumerate(invisible_text, 1):
            with st.expander(f"Detection #{i} - {detection.get('type', 'Unknown')}"):
                st.write(f"**Pattern:** {detection.get('pattern', 'N/A')}")
                st.write(f"**Content:**")
                st.code(detection.get('content', ''), language=None)
                
                if show_technical:
                    st.write(f"**Position:** {detection.get('position', 'N/A')}")


def display_yara_results(results: dict, show_technical: bool):
    """Display YARA scanning results with explanations and evidence"""
    st.subheader("YARA Rule Matches")
    
    yara_matches = results.get('yara_matches', [])
    
    if not yara_matches:
        st.success("✅ No YARA rules matched")
        return

    st.warning(f"⚠️ {len(yara_matches)} Suspicious Patterns Detected")
    
    for match in yara_matches:
        rule_name = match.get('rule', 'Unknown')
        strings = match.get('strings', [])
        
        # Group matches by their explanation (or lack thereof)
        grouped_alerts = {}
        unexplained_evidence = set()
        
        for string_match in strings:
            data = string_match.get('data', '').strip()
            found_explanation = False
            
            # Find matching explanation (check longer patterns first to avoid substring issues)
            # Sort keys by length in descending order to match "/JavaScript" before "/JS"
            sorted_keys = sorted(YARA_EXPLANATIONS.keys(), key=len, reverse=True)
            for key in sorted_keys:
                if key.lower() in data.lower():
                    explanation = YARA_EXPLANATIONS[key]
                    title = explanation['title']
                    if title not in grouped_alerts:
                        grouped_alerts[title] = {
                            "desc": explanation['desc'],
                            "evidence": set()
                        }
                    grouped_alerts[title]["evidence"].add(data)
                    found_explanation = True
                    break
            
            if not found_explanation:
                unexplained_evidence.add(data)

        # Display the Rule Container
        with st.expander(f"🔴 Detection: {rule_name}", expanded=True):
            
            # 1. Display Explained Alerts
            for title, info in grouped_alerts.items():
                st.info(f"**{title}**\n\n{info['desc']}")
                
                # Show the Evidence (The Smoking Gun)
                st.markdown("**🕵️ Flagged Content (Evidence):**")
                for item in sorted(info['evidence']):
                    st.code(item, language=None)
            
            # 2. Display Unexplained/Generic Matches
            if unexplained_evidence:
                st.write("**Suspicious Content Detected:**")
                st.caption("The following text triggered this security rule:")
                for item in sorted(unexplained_evidence):
                    st.code(item, language=None)
            
            # 3. Technical Details (Optional)
            if show_technical:
                st.divider()
                st.caption("Technical Metadata")
                meta = match.get('meta', {})
                if meta:
                    for k, v in meta.items():
                        st.write(f"- **{k}:** {v}")
                
                st.write("**Full Raw Matches:**")
                for s in strings:
                    st.text(f"Offset {s.get('offset')}: {s.get('data')}")


def display_semantic_results(results: dict, show_technical: bool, threshold: float):
    """Display semantic injection detection results"""
    st.subheader("Semantic Prompt Injection Detection")
    
    if not ENABLE_SEMANTIC:
        st.info("ℹ️ Semantic detection is disabled. Enable it with ENABLE_SEMANTIC_DETECTION=true environment variable.")
        return
    
    st.caption(f"Using threshold: {threshold}")
    
    semantic_detections = results.get('semantic_detections', [])
    
    if not semantic_detections:
        st.success("✅ No semantic injection patterns detected")
    else:
        st.warning(f"⚠️ Found {len(semantic_detections)} potential injection(s)")
        
        for i, detection in enumerate(semantic_detections, 1):
            similarity = detection.get('similarity', 0)
            
            # Color code based on similarity
            if similarity >= 0.9:
                severity = "🔴 Critical"
            elif similarity >= 0.8:
                severity = "🟠 High"
            else:
                severity = "🟡 Medium"
            
            with st.expander(f"{severity} - Detection #{i} (Similarity: {similarity:.2%})"):
                st.write("**Suspicious Sentence:**")
                st.info(detection.get('sentence', 'N/A'))
                
                st.write("**Similar to pattern:**")
                st.code(detection.get('matched_pattern', 'N/A'), language=None)
                
                if show_technical:
                    st.write(f"**Index:** {detection.get('index', 'N/A')}")


def display_privacy_results(results: dict, show_technical: bool):
    """Display privacy (PII) and structural risk detection results"""
    st.subheader("Privacy & Structural Analysis")
    
    # PII Detection Section
    st.markdown("#### PII (Personally Identifiable Information)")
    pii_detections = results.get('pii_detections', {})
    
    if not pii_detections or all(count == 0 for count in pii_detections.values()):
        st.success("✅ No PII detected")
    else:
        st.warning("⚠️ PII found in document")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Email Addresses",
                pii_detections.get('EMAIL_ADDRESS', 0),
                help="Number of email addresses detected"
            )
        
        with col2:
            st.metric(
                "Phone Numbers",
                pii_detections.get('PHONE_NUMBER', 0),
                help="Number of phone numbers detected"
            )
        
        with col3:
            st.metric(
                "Person Names",
                pii_detections.get('PERSON', 0),
                help="Number of person names detected"
            )
    
    # Structural Risks Section
    st.markdown("#### Structural Risks")
    structural_risks = results.get('structural_risks', {})
    
    # Check for error
    if 'error' in structural_risks:
        st.error(f"⚠️ Structural analysis error: {structural_risks['error']}")
    
    # Display dangerous tags
    has_risks = False
    for tag in ['/JS', '/JavaScript', '/AA', '/OpenAction']:
        count = structural_risks.get(tag, 0)
        if count > 0:
            has_risks = True
    
    if not has_risks:
        st.success("✅ No dangerous structural elements detected")
    else:
        st.error("🚨 Dangerous structural elements found!")
    
    # Always show the metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        js_count = structural_risks.get('/JS', 0)
        st.metric(
            "/JS",
            js_count,
            help="JavaScript code references",
            delta="⚠️ Risk" if js_count > 0 else None
        )
    
    with col2:
        javascript_count = structural_risks.get('/JavaScript', 0)
        st.metric(
            "/JavaScript",
            javascript_count,
            help="JavaScript actions",
            delta="⚠️ Risk" if javascript_count > 0 else None
        )
    
    with col3:
        aa_count = structural_risks.get('/AA', 0)
        st.metric(
            "/AA",
            aa_count,
            help="Additional Actions (auto-execute)",
            delta="⚠️ Risk" if aa_count > 0 else None
        )
    
    with col4:
        openaction_count = structural_risks.get('/OpenAction', 0)
        st.metric(
            "/OpenAction",
            openaction_count,
            help="Actions executed on document open",
            delta="⚠️ Risk" if openaction_count > 0 else None
        )
    
    if has_risks:
        st.warning("""
        **⚠️ Security Warning:**  
        These structural elements can execute code automatically when the PDF is opened.
        - **/JS** and **/JavaScript**: Can run arbitrary JavaScript code
        - **/AA**: Additional Actions that auto-execute
        - **/OpenAction**: Actions triggered when document is opened
        """)


def display_summary(results: dict, risk_level: str, risk_score: int):
    """Display analysis summary"""
    st.subheader("Analysis Summary")
    
    # Create summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Invisible Text Instances",
            len(results.get('invisible_text', []))
        )
    
    with col2:
        st.metric(
            "YARA Matches",
            len(results.get('yara_matches', []))
        )
    
    with col3:
        st.metric(
            "Semantic Detections",
            len(results.get('semantic_detections', []))
        )
    
    with col4:
        # Count total PII instances
        pii_detections = results.get('pii_detections', {})
        total_pii = sum(pii_detections.values()) if pii_detections else 0
        st.metric(
            "PII Instances",
            total_pii
        )
    
    # Recommendations
    st.subheader("Recommendations")
    
    if risk_level == "CLEAN":
        st.success("""
        ✅ **PDF appears clean**  
        No significant threats detected. The file appears safe for processing.
        """)
    
    elif risk_level == "LOW":
        st.info("""
        ℹ️ **Low risk detected**  
        Minor concerns found. Review the detections but file is likely safe.
        """)
    
    elif risk_level == "MEDIUM":
        st.warning("""
        ⚠️ **Medium risk detected**  
        Several suspicious patterns found. Carefully review all detections before processing.
        """)
    
    elif risk_level in ["HIGH", "CRITICAL"]:
        st.error(f"""
        🚨 **{risk_level} risk detected**  
        Significant threats found! Do not process this PDF without thorough investigation.
        Consider:
        - Reviewing all invisible text
        - Checking YARA matches
        - Analyzing semantic detections
        - Reviewing structural risks (especially /JS and /JavaScript tags)
        - Checking for PII exposure
        - Contacting security team if necessary
        """)
    
    # File information
    st.subheader("File Information")
    st.write(f"**File Path:** {results.get('file_path', 'N/A')}")
    st.write(f"**File Size:** {results.get('file_size', 0) / 1024:.2f} KB")
    st.write(f"**Uncompressed:** {'Yes' if results.get('uncompressed') else 'No'}")


if __name__ == "__main__":
    main()
