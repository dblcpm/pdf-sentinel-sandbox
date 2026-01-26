rule SuspiciousKeywords {
    meta:
        description = "Detects suspicious keywords that may indicate prompt injection"
        author = "PDF Sentinel"
        date = "2024-01-26"
    
    strings:
        // Common prompt injection patterns
        $prompt1 = "ignore previous" nocase
        $prompt2 = "ignore all previous" nocase
        $prompt3 = "disregard" nocase
        $prompt4 = "forget everything" nocase
        $prompt5 = "new instructions" nocase
        $prompt6 = "system prompt" nocase
        $prompt7 = "you are now" nocase
        $prompt8 = "act as" nocase
        $prompt9 = "pretend to be" nocase
        $prompt10 = "roleplay" nocase
        
        // LLM-specific injection attempts
        $llm1 = "GPT" nocase
        $llm2 = "ChatGPT" nocase
        $llm3 = "language model" nocase
        $llm4 = "AI assistant" nocase
        $llm5 = "assistant:" nocase
        $llm6 = "user:" nocase
        
        // Data exfiltration attempts
        $exfil1 = "send to" nocase
        $exfil2 = "email to" nocase
        $exfil3 = "POST to" nocase
        $exfil4 = "curl" nocase
        $exfil5 = "wget" nocase
        
        // Instruction overrides
        $override1 = "override" nocase
        $override2 = "bypass" nocase
        $override3 = "disable" nocase
        $override4 = "turn off" nocase
        
    condition:
        any of them
}

rule HiddenCommands {
    meta:
        description = "Detects hidden commands or scripts in PDF"
        author = "PDF Sentinel"
        date = "2024-01-26"
    
    strings:
        $script1 = "/JavaScript" nocase
        $script2 = "/JS" nocase
        $script3 = "/OpenAction" nocase
        $script4 = "/AA" nocase
        $script5 = "/Launch" nocase
        $script6 = "/SubmitForm" nocase
        $script7 = "/ImportData" nocase
        
    condition:
        any of them
}

rule EncodedContent {
    meta:
        description = "Detects encoded or obfuscated content"
        author = "PDF Sentinel"
        date = "2024-01-26"
    
    strings:
        $encode1 = "/ASCIIHexDecode"
        $encode2 = "/ASCII85Decode"
        $encode3 = "/LZWDecode"
        $encode4 = "/FlateDecode"
        $encode5 = "/RunLengthDecode"
        $encode6 = "/CCITTFaxDecode"
        $encode7 = "/JBIG2Decode"
        $encode8 = "/DCTDecode"
        
    condition:
        3 of them
}
