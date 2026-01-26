"""
PDF Sentinel - Streamlit Application
Forensic PDF Analysis Tool for detecting prompt injection and malicious content
"""

import streamlit as st
import os
import tempfile
from pathlib import Path
from analyzer import PDFAnalyzer


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
        
        st.header("Settings")
        semantic_threshold = st.slider(
            "Semantic Detection Threshold",
            min_value=0.5,
            max_value=0.95,
            value=0.7,
            step=0.05,
            help="Higher values = stricter detection"
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
            analyzer = PDFAnalyzer(yara_rules_path="signatures.yara")
            
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
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Invisible Text",
        "🎯 YARA Matches",
        "🧠 Semantic Detection",
        "📋 Summary"
    ])
    
    with tab1:
        display_invisible_text_results(results, show_technical)
    
    with tab2:
        display_yara_results(results, show_technical)
    
    with tab3:
        display_semantic_results(results, show_technical, semantic_threshold)
    
    with tab4:
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
    """Display YARA scanning results"""
    st.subheader("YARA Rule Matches")
    
    yara_matches = results.get('yara_matches', [])
    
    if not yara_matches:
        st.success("✅ No YARA rules matched")
    else:
        st.warning(f"⚠️ {len(yara_matches)} YARA rule(s) matched")
        
        for i, match in enumerate(yara_matches, 1):
            rule_name = match.get('rule', 'Unknown')
            meta = match.get('meta', {})
            
            with st.expander(f"Rule: {rule_name}"):
                if meta:
                    st.write("**Metadata:**")
                    for key, value in meta.items():
                        st.write(f"- {key}: {value}")
                
                strings = match.get('strings', [])
                if strings:
                    st.write(f"**Matched Strings ({len(strings)}):**")
                    for string_match in strings:
                        identifier = string_match.get('identifier', 'Unknown')
                        data = string_match.get('data', '')
                        st.code(f"{identifier}: {data}", language=None)
                        
                        if show_technical:
                            st.write(f"Offset: {string_match.get('offset', 'N/A')}")


def display_semantic_results(results: dict, show_technical: bool, threshold: float):
    """Display semantic injection detection results"""
    st.subheader("Semantic Prompt Injection Detection")
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


def display_summary(results: dict, risk_level: str, risk_score: int):
    """Display analysis summary"""
    st.subheader("Analysis Summary")
    
    # Create summary metrics
    col1, col2, col3 = st.columns(3)
    
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
        - Contacting security team if necessary
        """)
    
    # File information
    st.subheader("File Information")
    st.write(f"**File Path:** {results.get('file_path', 'N/A')}")
    st.write(f"**File Size:** {results.get('file_size', 0) / 1024:.2f} KB")
    st.write(f"**Uncompressed:** {'Yes' if results.get('uncompressed') else 'No'}")


if __name__ == "__main__":
    main()
