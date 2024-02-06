# BOMRa
The Behavioral Model for Ransomware (BOMRa), designed using semantic web techniques, is capable of representing the comprehensive behavioral activity of ransomware along with the malicious intent behind the attack. The model portrays the system-level operations performed in the victim machine to achieve a malicious objective. The research work proposed demonstrates the systematization of malware activity specifically for ransomware. The method proposes a domain ontology that is engineered using a "middle-out" approach. 

In BOMRa, the ransomware behavior information is formally represented as malicious *Tactic*, *Behavior*, and *Windows Artifact*. In this, the concept *Tactic* represents the high-level actions adopted by the ransomware to attain its malicious objectives, which also covers adversarial techniques and sub-techniques. The abstract conceptual activities that take place on a system when ransomware executes on the victim machine are aggregated and formally represented using the concept *Behavior*. The actual system-level operations carried out by the ransomware when it performs the abstract activities are represented using the concept *Windows Artifact*. Also, the proposed model is designed to be consistent and interoperable with other publicly available standard cybersecurity knowledge bases.

|Concept|Class Expression|
|---|---|
|**Tactic**|Things that are (_adoptedBy_ some **Ransomware**) and (_implementedBy_ some **Behavior**) and (_accomplishes_ some **MaliciousObjective**)|
|**Behavior**|Things that (_implements_ some **Tactic**) and (_calls_ some **WindowsAPI** or _executes_ some **WindowsCommand** or _processes_ some **WindowsRegistry**) and (_performedBy_ some **Ransomware**) and (_detectedBy_ some **Pattern**)|
|**Windows Artifact**|Things that are (_usedBy_ some **Behavior**)|
|**Ransomware**|Things that are (**DigitalArtifacts**) and (_adopts_ some **Tactic**) and (_performs_ some **Behavior**) and (_achieves_ some **MaliciousObjective**) and (_triggers_ some **Pattern**)|
|**Pattern**|Things that are (_triggeredBy_ some **Ransomware**) and (_detects_ some **Behavior**)|
|---|---|

The proposed ontology is qualitatively evaluated to ensure its relevance and robustness. The efficacy and effectiveness of the proposed methodology is qualitatively evaluated based on its performance against a set of competency questions (CQs). 

**Competency Questions**

The	CQs detailed in this section are designed based on the challenges faced by state-of-the-art malware research identified through literature reviews and the limitations of existing cyber security adversarial knowledge bases. BOMRa is designed to provide solutions for all the competency questions that aim to address some of the limitations of the current ransomware research. The competence of the proposed method, however, is not limited to following questions.

**_CQ1: Which are all the ransomware samples that perform a particular system-level operation?_**

This CQ challenges the ability of Knowledge Base to identify and retrieve distinct ransomware samples that perform a particular system-level operation. For instance, the BOMRa can answer questions such as, _“Which ransomware samples perform file deletion operations using DeleteFileW?”_. In BOMRa, semantic equivalence is defined between entities that perform a fundamentally similar operation. All the DeleteFile APIs such as NtDeleteFile, DeleteFileA, DeleteFileW, or ZwDeleteFile Windows APIs are defined as semantically equivalent in BOMRa using appropriate axioms. This reduces the need to manually track and list all Windows API calls that may be used to delete a file from the Installable File System. The following SPARQL query snippet demonstrates the aforesaid logic.

```sparql
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX bomra: <http://research.amrita.edu/bsr/ontologies/2022/ransomware-behavioural-ontology/#>

SELECT DISTINCT ?ransomware
WHERE{
  ?ransomware a bomra:Ransomware .
  ?equiv_classes a owl:equivalentClass bomra:DeleteFileW .
  ?api_calls a ?equiv_classes .
  ?ransomware bomra:calls ?api_calls
}
ORDER BY ASC(?ransomware)
```

The query listed in Fig. 8 is used to infer a solution for CQ1. The query initially identifies the entities that are defined as equivalent to DeleteFileW in BOMRa. It subsequently searches the Knowledge Base to identify and list distinct samples that call one of the four Windows APIs that are used for file deletion operation.

**_CQ2: Which all ransomware samples perform a particular behavior?_**

This CQ challenges the ability of Knowledge Base to process abstract behavioral information of ransomware. For instance, the BOMRa can answer questions such as, _“Which all ransomware samples exhibit file encryption behavior?”_. In BOMRa, the concept File Encryption abstracts all system-level operations that can perform cryptographic encryption of files existing on the system. Also, the relationship ‘exhibits’ maps all ransomware samples that exhibit a particular abstract behavior. The SPARQL query mentioned in subsequent code snippet searches the Knowledge Base to list distinct samples that exhibit file encryption operation.

```sparql
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX bomra: <http://research.amrita.edu/bsr/ontologies/2022/ransomware-behavioural-ontology/#>

SELECT DISTINCT ?ransomware
WHERE{
  ?ransomware a bomra:Ransomware .
  ?behavior_1 a bomra:File .
  ?api_calls a ?equiv_classes .
  ?ransomware bomra:calls ?api_calls
}
ORDER BY ASC(?ransomware)
```

**_CQ3: Which all ransomware samples adopt a particular adversarial strategy?_**

The Knowledge Base is capable of inferring ransomware samples that adopt a particular adversarial tactic. An adversary performs a sequence of operations to achieve a malicious motive. BOMRa consists of predefined relationships between adversarial tactics, abstract behaviors, and actual system-level operations. 

For instance, the BOMRa can answer questions such as, _“Which ransomware samples adopt an adversarial strategy for Code Execution Forestallment?”_. In BOMRa, the concept Code Execution Forestallment defines the adversarial tactic commonly adopted to evade detection. The Knowledge System initially perceives all distinct techniques that are defined under Code Execution Forestallment. Then, it infers the sequence of system-level operations associated with each of these techniques using the property chains mentioned in Section III (F). The Knowledge System then applies the inferred knowledge to identify and list distinct ransomware samples that adopt Code Execution Forestallment technique. The corresponding query is illustrated by following SPARQL query snippet.

```sparql
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX bomra: <http://research.amrita.edu/bsr/ontologies/2022/ransomware-behavioural-ontology/#>

SELECT DISTINCT ?ransomware
WHERE{
  ?ransomware a bomra:Ransomware .
  ?equiv_classes a owl:equivalentClass bomra:DeleteFileW .
  ?api_calls a ?equiv_classes .
  ?ransomware bomra:calls ?api_calls
}
ORDER BY ASC(?ransomware)
```
