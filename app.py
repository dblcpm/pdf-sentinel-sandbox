"""
PDF Sentinel - Streamlit Application
Forensic PDF Analysis Tool for detecting prompt injection and malicious content
"""

import streamlit as st
import os
import tempfile
from pathlib import Path
from pdf_sentinel import PDFAnalyzer


# Check if semantic detection should be enabled
ENABLE_SEMANTIC = os.getenv('ENABLE_SEMANTIC_DETECTION', 'true').lower() in ('true', '1', 'yes')


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
        
        enable_crossref = st.checkbox(
            "CrossRef DOI Verification",
            value=False,
            help="Verify cited DOIs against CrossRef API (requires internet, adds latency)"
        )

        show_technical = st.checkbox(
            "Show Technical Details",
            value=False,
            help="Display detailed technical analysis"
        )
    
    # File uploader
    st.header("Upload PDF File")
    uploaded_file = st.file_uploader(
        "Choose a PDF file to analyze (max 200 MB)",
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

        # File size guard (200 MB)
        if uploaded_file.size > PDFAnalyzer.MAX_FILE_SIZE:
            st.error(
                f"File too large ({uploaded_file.size / (1024*1024):.1f} MB). "
                f"Maximum allowed size is {PDFAnalyzer.MAX_FILE_SIZE / (1024*1024):.0f} MB."
            )
        elif st.button("🔍 Analyze PDF", type="primary"):
            analyze_pdf_file(uploaded_file, semantic_threshold, show_technical, enable_crossref)


def analyze_pdf_file(uploaded_file, semantic_threshold: float, show_technical: bool, enable_crossref: bool = False):
    """
    Analyze the uploaded PDF file

    Args:
        uploaded_file: Streamlit uploaded file object
        semantic_threshold: Threshold for semantic detection
        show_technical: Whether to show technical details
        enable_crossref: Whether to verify DOIs against CrossRef
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
            analyzer = PDFAnalyzer(
                yara_rules_path="signatures.yara",
                enable_semantic=ENABLE_SEMANTIC,
                enable_crossref=enable_crossref,
            )
            
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
        with st.expander("⚠️ Analysis Notices", expanded=True):
            for error in results['errors']:
                st.warning(f"⚠️ {error}")
    
    # Tabs for different detection types
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🔍 Invisible Text",
        "🎯 YARA Matches",
        "🧠 Semantic Detection",
        "🔒 Privacy",
        "⚠️ Advanced Threats",
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
        display_advanced_threats(results, show_technical)
    
    with tab6:
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
            description = detection.get('description', detection.get('type', 'Unknown'))
            with st.expander(f"Detection #{i} — Invisible Text Found"):
                st.markdown(f"**What was found:** {description}")
                
                extracted = detection.get('extracted_text', detection.get('content', ''))
                if extracted:
                    st.markdown("**Hidden text extracted from the PDF:**")
                    st.code(extracted, language=None)
                
                if show_technical:
                    st.write(f"**Type:** `{detection.get('type', 'N/A')}`")
                    st.write(f"**Pattern:** `{detection.get('pattern', 'N/A')}`")
                    st.write(f"**Position:** {detection.get('position', 'N/A')}")


def display_yara_results(results: dict, show_technical: bool):
    """Display YARA scanning results"""
    st.subheader("YARA Rule Matches")
    
    yara_matches = results.get('yara_matches', [])
    
    if not yara_matches:
        st.success("✅ No YARA rules matched")
    else:
        st.warning(f"⚠️ {len(yara_matches)} YARA rule(s) matched")
        
        for i, match in enumerate(yara_matches, 1):
            rule_name = match.get('rule', 'Unknown')
            description = match.get('description', '')
            
            with st.expander(f"Rule: {rule_name}"):
                if description:
                    st.markdown(f"**What was found:** {description}")
                
                strings = match.get('strings', [])
                if strings:
                    st.markdown(f"**Matched text from the PDF ({len(strings)} occurrence(s)):**")
                    for string_match in strings:
                        explanation = string_match.get('explanation', '')
                        data = string_match.get('data', '')
                        if explanation:
                            st.info(f"📌 {explanation}")
                        else:
                            st.code(f"{data}", language=None)
                        
                        if show_technical:
                            st.write(f"Identifier: `{string_match.get('identifier', 'N/A')}`")
                            st.write(f"Offset: {string_match.get('offset', 'N/A')}")
                
                if show_technical:
                    meta = match.get('meta', {})
                    if meta:
                        st.write("**Rule Metadata:**")
                        for key, value in meta.items():
                            st.write(f"- {key}: {value}")


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


def display_advanced_threats(results: dict, show_technical: bool):
    """Display image anomalies, obfuscated payloads, and citation spam results"""
    st.subheader("Advanced Threat Detection")

    # Image anomalies
    st.markdown("#### 🖼️ Image Anomalies")
    image_anomalies = results.get('image_anomalies', [])

    if not image_anomalies:
        st.success("✅ No suspicious images detected")
    else:
        st.warning(f"⚠️ Found {len(image_anomalies)} suspicious image(s)")
        for i, anomaly in enumerate(image_anomalies, 1):
            description = anomaly.get('description', 'Suspicious image detected')
            with st.expander(f"Image #{i} — Page {anomaly.get('page', '?')}"):
                st.markdown(f"**What was found:** {description}")
                if show_technical:
                    st.write(f"**Object:** `{anomaly.get('object_name', 'N/A')}`")
                    st.write(f"**Entropy:** {anomaly.get('entropy', 'N/A')}")
                    st.write(f"**Size:** {anomaly.get('size_bytes', 0)} bytes")

    # Obfuscated payloads
    st.markdown("#### 🔐 Obfuscated Payloads")
    obfuscated = results.get('obfuscated_payloads', [])

    if not obfuscated:
        st.success("✅ No obfuscated payloads detected")
    else:
        st.warning(f"⚠️ Found {len(obfuscated)} obfuscated payload(s)")
        for i, payload in enumerate(obfuscated, 1):
            description = payload.get('description', 'Obfuscated content detected')
            with st.expander(f"Payload #{i} — Encoded Content Found"):
                st.markdown(f"**What was found:** {description}")

                decoded = payload.get('decoded', '')
                if decoded:
                    st.markdown("**Decoded text from the PDF:**")
                    st.code(decoded, language=None)

                if show_technical:
                    st.write(f"**Encoded (preview):** `{payload.get('encoded', 'N/A')}`")
                    st.write(f"**Position:** {payload.get('position', 'N/A')}")

    # Citation spam
    st.markdown("#### 📊 Citation & Link Analysis")
    citation_spam = results.get('citation_spam', {})

    if not citation_spam or not citation_spam.get('is_spam', False):
        st.success("✅ No citation spam or link farming detected")
    else:
        st.error("🚨 Potential citation spam or link farming detected!")
        indicators = citation_spam.get('spam_indicators', [])
        if indicators:
            st.markdown("**What was found:**")
            for indicator in indicators:
                st.warning(f"📌 {indicator}")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("URLs Found", citation_spam.get('url_count', 0))
        with col2:
            st.metric("DOIs Found", citation_spam.get('doi_count', 0))
        with col3:
            st.metric("Unique Domains", citation_spam.get('unique_domains', 0))

    # CrossRef verification results
    crossref_data = citation_spam.get('crossref', {})
    if crossref_data and not crossref_data.get('error'):
        st.markdown("#### 🔗 CrossRef DOI Verification")

        cr_col1, cr_col2, cr_col3 = st.columns(3)
        with cr_col1:
            st.metric("DOIs Checked", crossref_data.get('total_checked', 0))
        with cr_col2:
            st.metric("Valid", crossref_data.get('valid_count', 0))
        with cr_col3:
            invalid_count = crossref_data.get('invalid_count', 0)
            retracted_count = crossref_data.get('retracted_count', 0)
            st.metric(
                "Invalid / Retracted",
                f"{invalid_count} / {retracted_count}",
                delta="Risk" if (invalid_count > 0 or retracted_count > 0) else None,
            )

        cr_indicators = crossref_data.get('indicators', [])
        for ind in cr_indicators:
            severity = ind.get('severity', 'medium')
            if severity == 'critical':
                st.error(f"🚨 {ind['description']}")
            elif severity == 'high':
                st.warning(f"⚠️ {ind['description']}")
            else:
                st.info(f"ℹ️ {ind['description']}")

        if show_technical and crossref_data.get('metadata'):
            with st.expander("CrossRef metadata details"):
                for doi, meta in crossref_data['metadata'].items():
                    retracted_tag = " **[RETRACTED]**" if meta.get('retracted') else ""
                    st.markdown(
                        f"- `{doi}`{retracted_tag}: *{meta.get('title', 'N/A')}* "
                        f"— {meta.get('journal', 'N/A')} ({meta.get('year', '?')})"
                    )
    elif crossref_data.get('error'):
        st.markdown("#### 🔗 CrossRef DOI Verification")
        st.warning(f"CrossRef lookup failed: {crossref_data['error']}")


def display_summary(results: dict, risk_level: str, risk_score: int):
    """Display analysis summary"""
    st.subheader("Analysis Summary")
    
    # Create summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Invisible Text",
            len(results.get('invisible_text', [])),
            help="Instances of text hidden from visual display"
        )
    
    with col2:
        st.metric(
            "Suspicious Patterns",
            len(results.get('yara_matches', [])),
            help="YARA rule matches for suspicious keywords or structures"
        )
    
    with col3:
        st.metric(
            "Injection Attempts",
            len(results.get('semantic_detections', [])),
            help="Semantic prompt injection detections"
        )
    
    with col4:
        # Count total PII instances
        pii_detections = results.get('pii_detections', {})
        total_pii = sum(pii_detections.values()) if pii_detections else 0
        st.metric(
            "PII Instances",
            total_pii,
            help="Personally identifiable information found"
        )
    
    # Additional threat counts
    col5, col6, col7 = st.columns(3)
    
    with col5:
        st.metric(
            "Suspicious Images",
            len(results.get('image_anomalies', [])),
            help="Images with abnormally high entropy (possible steganography)"
        )
    
    with col6:
        st.metric(
            "Obfuscated Payloads",
            len(results.get('obfuscated_payloads', [])),
            help="Base64-encoded content hiding suspicious data"
        )
    
    with col7:
        citation_spam = results.get('citation_spam', {})
        st.metric(
            "Citation Spam",
            "Yes" if citation_spam.get('is_spam', False) else "No",
            help="Whether excessive URLs or link farming was detected"
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
