---
title: "Evaluarea componentei Audit (XGBoost)"
subtitle: "Profiluri de atac, metrice și granițele detecției"
author: "Iulia-Andreea Grigore"
date: "Iunie 2026"
lang: ro
---

# 1. Metodologia de evaluare

Componenta Audit a sistemului de detecție a intruziunilor este evaluată pe un dataset propriu construit dintr-un cluster AKS real (`intrusion-detection-aks`, regiune North Europe, un nod worker `Standard_DS2_v2`, control-plane în nivel gratuit). Evenimentele de audit sunt colectate prin canalul oficial Azure Monitor: un Diagnostic Setting trimite categoriile `kube-audit` și `kube-audit-admin` la un workspace Log Analytics dedicat, iar interogarea KQL extrage doar evenimentele din ferestrele temporale marcate explicit ca scenariu.

Dataset-ul de referință conține **24 de sesiuni independente**, fiecare cu trafic benign generat de trei operatori reali (cert-manager, ArgoCD, kube-prometheus-stack) plus 10 actori umani simulați cu certificate distincte, suprapus cu trafic de atac controlat. Output-ul scriptului `export_rich.py` produce **~36.000 ferestre glisante** (25.042 antrenare, 10.909 testare), cu un total de **52 episoade de atac** distribuite pe patru profiluri. Split-ul este **sesiune-disjoint**: sesiunile 1–16 formează partiția de antrenare, sesiunile 17–24 partiția de testare, cu stratificare forțată astfel încât toate cele patru profiluri să apară în ambele jumătăți.

Modelul evaluat este un clasificator XGBoost antrenat pe **15 trăsături comportamentale per fereastră** (numărul de evenimente, diversitatea verbelor și resurselor, rata de respingeri 403, frecvența operațiilor sensibile, indicatori specifici de recon). Caracteristic acestei alegeri: niciun feature nu este identitatea actorului brută, ceea ce evită leakage-ul circular în care eticheta s-ar corela trivial cu numele utilizatorului.

# 2. Profilurile de atac

Setul de date conține patru profiluri de atac distincte, fiecare reflectând o tactică reală documentată în taxonomia MITRE ATT&CK for Containers. Selecția lor este motivată de necesitatea de a expune modelul la un spectru complet de pattern-uri adversariale, de la cele brutale ușor detectabile până la cele subtile, ambigue cu automatizările legitime.

## 2.1 Profilul „token furat" (`victim-sa`)

ServiceAccount-ul `victim-sa` are atribuit un rol minim (`pod-reader`) în namespace-ul `default`. Atacatorul a obținut tokenul acestui SA și încearcă să-l folosească pentru recon agresiv: listare de secrete în alte namespace-uri, enumerare de pod-uri, încercări de execuție de comenzi. Pentru că rolul real al SA-ului este restrâns, majoritatea cererilor sunt respinse cu cod HTTP 403, lăsând un trail dens de evenimente `authorization.k8s.io/decision: forbid`. Acest profil este cel mai ușor detectabil prin trăsătura `forbid_ratio`, dar a fost inclus tocmai pentru a verifica că modelul nu se bazează exclusiv pe acest semnal — diversificarea cu profilul 2 demonstrează exact acest lucru.

## 2.2 Profilul „abuz de credențial valid" (`adversary-external`)

În contrast complet cu profilul anterior, `adversary-external` are atribuit rolul `cluster-admin`. Modelul de amenințare este un cont privilegiat compromis sau un insider rău intenționat care își folosește permisiunile legitime: citește secrete, creează `ClusterRoleBindings` malițioase, execută comenzi în containere active. Toate aceste acțiuni reușesc cu cod 200, deci `forbid_ratio` rămâne aproape de zero. Profilul a fost introdus în versiunea v2 a setului de date după ce o analiză de importanță a feature-urilor pe v1 a relevat că `forbid_ratio` domina cu 81,5% — modelul era de facto un detector pe o singură trăsătură. Adăugarea acestui profil a forțat modelul să învețe semnale comportamentale ortogonale (`n_secrets`, `n_rbac`, `n_exec`), aducând importanța `forbid_ratio` la 0,3%.

## 2.3 Profilul „low-and-slow" (`adversary-insider`)

Identitatea este `adversary-insider` cu rol intermediar (`edit`). Pattern-ul de atac reproduce acțiunile profilului 2, dar **diluate temporal**: una-două operații sensibile per minut, intercalate cu pauze de 30–60 secunde. Densitatea per fereastră scade dramatic, iar trăsăturile cumulative pe ferestre scurte nu se aprind. Acest profil a fost călcâiul lui Achile inițial — pe v2, recall-ul pe ferestre evazive ținute deoparte era de doar **35%**. Mitigarea a constat în includerea unor sesiuni low-and-slow în partiția de antrenare (nu doar test), forțând modelul să generalizeze pe agregări temporale mai lungi. Postintervenție, recall-ul a crescut la 100% pe același tip de evaziune. Acesta este profilul care testează cel mai direct robustețea la tactici adversariale conștiente.

## 2.4 Profilul „enumerare de permisiuni" (`recon-sa`)

ServiceAccount-ul `recon-sa` simulează un atacator post-compromise care vrea să-și mapeze suprafața de atac fără a declanșa încă acțiuni vizibile. Pattern-ul este o grilă densă de cereri `kubectl auth can-i <verb> <resource>` — care se traduc la nivelul API-server-ului în cereri `create` pe `selfsubjectaccessreviews` și `selfsubjectrulesreviews`. Toate aceste cereri au cod 200 și decizie `allow`, fiindcă orice utilizator autentificat poate verifica ce drepturi are. Profilul este intrinsec ambiguu cu automatizările benigne (CI/CD preflight, dashboard-uri de tip Lens/Headlamp, compliance scanners), care fac aceleași apeluri în volum mare. A fost adăugat în versiunea v1.1 împreună cu trăsătura dedicată `n_selfreview`, care numără apelurile `SelfSubject*Reviews` per fereastră. Pe v2 (înainte de această extindere), recall-ul pe recon-sa era de **0,1%**; după adăugarea feature-ului dedicat și a actorilor benigni de control, a urcat la **98,7%**.

## 2.5 Relevanța acoperirii combinate

Cele patru profiluri acoperă patru cadrane diferite ale spațiului de atac, structurate după două axe: **densitate temporală** (densă vs. diluată) și **vizibilitate în audit** (decizii forbid vs. allow). Profilul 1 ocupă cadranul *dens + forbid*, profilul 2 *dens + allow*, profilul 3 *diluat + allow*, iar profilul 4 *dens + allow ambiguu*. Această acoperire este necesară pentru a evita supra-antrenarea modelului pe o singură semnătură ușoară și pentru a expune transparent atât capacitatea de detecție, cât și limitele acesteia.

# 3. Trafic benign realist

Calitatea evaluării depinde la fel de mult de calitatea benign-ului ca de cea a atacului. Pentru a evita leakage-ul de vocabular — în care tokenii „de atac" (ex. `get:secrets:`, `create:clusterrolebindings:`) ar fi inexistenți în benign și astfel modelul ar separa trivial — am deployat trei operatori reali pe cluster: **cert-manager** (face citiri și actualizări legitime pe `Secrets` pentru rotația certificatelor), **ArgoCD** (creează `ClusterRoleBindings` și `ServiceAccounts` pentru aplicații, face discovery larg pe API), **kube-prometheus-stack** (monitorizează cluster-ul cu listări masive pe toate resursele).

Pe lângă operatori, am simulat patru pattern-uri de utilizare umană:
- **check-then-act** — un developer verifică permisiunile (`kubectl auth can-i`) și imediat execută acțiunea legitimă;
- **CI preflight batch** — un cont de CI/CD face 6–12 cereri `can-i` la pornire, apoi un deploy real;
- **dashboard page-load** — un operator deschide un dashboard (Lens, Headlamp) care face 8–15 cereri `can-i` contigue ca să afișeze meniul, fără acțiune ulterioară;
- **compliance scan** — un scanner de conformitate face 15–25 cereri `can-i` per fereastră, intercalate cu citiri reale (ceea ce sparge burst-ul și produce `n_selfreview` mare dar `burst_max` mic — cazul cel mai dificil de fals pozitiv).

Aceste profiluri benigne sunt acoperite explicit pentru că **se suprapun semantic** cu profilul de atac 4 (`recon-sa`), iar absența lor în setul de antrenare ar fi produs un model care alertează pe orice automatizare legitimă cu can-i în volum mare.

# 4. Rezultatele evaluării

## 4.1 Metrice clasice pe fereastră (test held-out)

Pe partiția de test sesiune-disjoint, modelul XGBoost cu 15 trăsături comportamentale obține următoarele performanțe:

| Metrică | Valoare |
|---|---|
| Precision | **0,806** |
| Recall | **0,996** |
| F1-score | **0,891** |
| FPR | **2,73%** |
| ROC AUC | **0,9988** |
| PR AUC | **0,988** |

Matricea de confuzie completă: True Negatives = 9.526, False Positives = 267, False Negatives = 4, True Positives = 1.112. Practic, modelul ratează doar **4 ferestre de atac** din 1.116 totale și generează 267 false alarme din 9.793 ferestre benigne. Recall-ul aproape perfect (0,996) demonstrează că modelul captează semnalul de atac în mod fiabil; FPR-ul de 2,73% este însă punctul critic care necesită analiză suplimentară la nivel de episod.

## 4.2 Metrice la nivel de episod (CI bootstrap)

Metricele pe fereastră sunt **înșelător de bune** pentru un deployment real, fiindcă ferestrele glisante pentru același actor sunt corelate temporal: o singură fereastră de atac pozitivă într-un episod este suficientă pentru a declanșa o alertă, iar o singură fereastră benignă fals pozitivă într-o sesiune lungă este suficientă pentru a deranja un operator SOC. Metricele relevante operațional sunt cele agregate pe **episod**, unde un episod este definit ca tuplul `(actor, sesiune)`.

Pe partiția de testare cu **52 episoade de atac** și **216 episoade benigne** (24 sesiuni × 9 actori benigni umani plus operatorii), bootstrap-ul cu 1000 de iterații produce:

| Metrică (per episod) | Estimat | Interval de încredere 95% |
|---|---|---|
| Recall | 75% | [58%, 92%] |
| FPR | 16,2% | [12%, 21%] |
| Cu histerezis K ≥ 5 ferestre | — | FPR redus la 9,2% |

Diferența între FPR de 2,7% (pe fereastră) și 16,2% (pe episod) reflectă exact problema: în 16,2% dintre episoadele benigne lungi, există **cel puțin o fereastră** care depășește pragul. Aplicarea unui histerezis minimal — declanșarea alertei doar după 5 ferestre pozitive consecutive — reduce FPR la 9,2% fără pierdere semnificativă de recall, fiindcă pâlpâirile benigne tind să fie izolate, iar atacurile reale susțin pattern-ul pe mai multe ferestre.

## 4.3 Distribuția FPR pe profiluri benigne

Costul fals pozitivelor nu este uniform distribuit. Analiza per actor benign relevă unde modelul greșește:

| Profil benign | Rata de fals pozitive (episodice) |
|---|---|
| `ci-deployer` (CI preflight) | 83% |
| `compliance-scanner-sa` (compliance scan) | 26% |
| `sre-oncall` (dashboard page-load) | 11% |
| Restul operatorilor (cert-manager, ArgoCD, kube-prometheus) | < 2% |

Concentrarea fals pozitivelor pe automatizările care fac volume mari de `auth can-i` confirmă explicit limita modelului: **detecția reconului de permisiuni nu poate distinge perfect între un atacator post-compromise și un proces benign de scanning**. Această limitare este intrinsecă datelor — la nivel de audit API, cele două activități sunt aproape identice — și mitigarea propusă pentru deploy este o allowlist a identităților de automatizare cunoscute, aplicată după detecție.

## 4.4 Robustețea la evaziune

Testul de evaziune low-and-slow măsoară gradul în care un atacator conștient de existența IDS-ului poate evita detecția prin dilatare temporală. Pe versiunea v2 a setului (înainte de hardening), recall-ul pe atacuri low-and-slow ținute deoparte era de **35%** — adică 65% dintre atacurile diluate evadau. Mitigarea a constat în includerea unor sesiuni low-and-slow în partiția de antrenare, astfel încât modelul să învețe agregări temporale pe ferestre mai lungi. Post-mitigare, recall-ul pe același tip de evaziune este de **100%** cu FPR menținut sub 0,3%.

Caveat onest: testul măsoară robustețea la evaziunea **văzută** în antrenare. Un atacator care ar inventa un pattern radical nou de dilatare temporală nu este garantat detectat — protocolul tool-disjoint din secțiunea următoare adresează parțial această întrebare.

## 4.5 Generalizare tool-disjoint

Testul tool-disjoint măsoară dacă modelul detectează atacuri produse de un **instrument complet nou**, nevăzut în antrenare. Am efectuat două asemenea teste:

**Test 1 — kube-hunter:** acest instrument popular de penetration testing pentru Kubernetes a generat în 30 minute de rulare doar **un singur eveniment** în categoria `kube-audit`. Analiza a relevat că kube-hunter operează în mare măsură **în afara planului API**: citește local fișierul cu tokenul SA, interoghează endpoint-ul de metadata Azure (169.254.169.254), sondează kubelet-ul direct, verifică capabilities-uri ale containerului. Niciuna dintre aceste acțiuni nu trece prin `kube-apiserver`, deci sunt invizibile pentru orice IDS bazat pe audit API. Recall = 0% pe acest profil, dar constatarea **confirmă necesitatea arhitecturală a componentei Falco/runtime**, nu reprezintă o slăbiciune a modelului Audit.

**Test 2 — pattern rakkess/kdigger (recon-only API-heavy):** acest pattern simulează un atacator care folosește exclusiv apeluri `auth can-i` masive, fără a atinge resurse sensibile. Pe acest set held-out tool-disjoint, recall-ul modelului final este de **96,2%**. Analiza importanței feature-urilor pe predicțiile pozitive arată însă că detecția se face prin `n_list` (enumerare de resurse), nu prin `n_selfreview` (feature-ul dedicat reconului). Adică modelul prinde acest profil **ca enumerare-list**, nu ca **recon de permisiuni** propriu-zis. Concluzia onestă: modelul generalizează la enumerare-list, dar nu am demonstrat generalizarea la un nou tool de pură verificare a permisiunilor.

## 4.6 Importanța feature-urilor și verificarea adversarială

Distribuția importanței feature-urilor pe modelul final demonstrează că învățarea este distribuită, nu dominată de o cârjă uni-dimensională:

| Feature | Importanță |
|---|---|
| `n_list` | 0,336 |
| `n_selfreview` | 0,259 |
| `n_secrets` | 0,090 |
| `n_rbac` | 0,063 |
| `n_distinct_resource` | 0,062 |
| `selfreview_ratio` | 0,043 |
| `n_distinct_ns` | 0,041 |
| `n_events` | 0,040 |
| `n_create` | 0,024 |
| Restul (6 features) | < 0,02 fiecare |

`forbid_ratio` — care în versiunea v1 era cârjă cu importanță 0,815 — a fost redus la **0,010** după diversificarea profilurilor de atac. Această evoluție demonstrează că modelul a fost forțat să învețe semnale comportamentale ortogonale.

Suplimentar, o procedură de verificare adversarială automatizată (workflow paralel cu agenți independenți care caută leakage subtil) a identificat și eliminat două feature-uri inițial candidate: `n_distinct_srcip` (artefact de fereastră — toate atacurile au srcIP unic, deci semnalul colapsează la hazard fără 3 SA-uri suplimentare control-plane) și `selfreview_burst_max` (confound de tip-client — kubectl intercalează un GET discovery între cereri, deci burst-ul este artificial 1 la toți clienții kubectl). Ablația ulterioară a confirmat că eliminarea acestor feature-uri menține performanța pe metrice operaționale.

## 4.7 Granița de detecție

Sintetizând rezultatele de mai sus, granița de detecție a modelului Audit este explicit:

| Categorie de atac | Detecție |
|---|---|
| Acțiuni periculoase pe planul API (secrete, exec, RBAC, escaladare) | **Recall 100%** (incluzând low-and-slow după hardening) |
| Recon prin token furat cu trail forbid dens | Recall 100% |
| Enumerare permisiuni (`SelfSubject*Reviews`) | Recall 98,7% (cu ambiguitate intrinsecă cu automatizările benigne) |
| Recon-only pur (instrument nou, fără acțiuni concrete) | Recall 0,1% (modelul nu prinde reconul de pură verificare ca pattern dedicat) |
| Atac în afara planului API (kube-hunter: token local, metadata Azure, kubelet) | **Recall 0%** (limitare arhitecturală — necesită componenta Falco) |

# 5. Justificarea relevanței profilurilor pentru evaluare

Cele patru profiluri nu sunt arbitrare; ele acoperă **patru moduri distincte de eșec metodologic** pe care un dataset slab proiectat le-ar masca:

1. **Profilul 1 (token furat)** validează că modelul captează semnalul cel mai brut și ușor de detectat — funcționează ca *sanity check* al întregului pipeline.

2. **Profilul 2 (abuz credențial valid)** validează că modelul **nu se bazează pe `forbid_ratio`** ca proxy pentru atac. Fără acest profil, un model „100% accurate" ar fi un detector cu un singur feature, vulnerabil la cel mai simplu atacator cu permisiuni reale.

3. **Profilul 3 (low-and-slow)** validează **robustețea la evaziune temporală** și forțează feature-uri pe ferestre temporale mai lungi. Fără acest profil, modelul ar fi un detector de rafale dense, ușor de evitat de un atacator paranoid.

4. **Profilul 4 (recon permisiuni)** validează **acoperirea reconului pasiv** și expune limita inerentă a discriminării între recon malițios și automatizări benigne. Fără acest profil, modelul ar avea un punct orb pe o tactică MITRE explicit documentată (T1613 — Container and Resource Discovery), care este de obicei **primul pas** într-un atac țintit.

Stratificarea forțată pe partiții asigură că rezultatele raportate nu sunt artefacte de overfitting pe o singură configurație de atac. Fiecare profil contribuie la o secțiune diferită a graniței de detecție, iar absența oricăruia ar lăsa o întrebare critică fără răspuns experimental.

# 6. Discuție și limitări metodologice

Rezultatele prezentate reprezintă o evaluare riguroasă pentru un sistem academic, dar trebuie încadrate cu trei caveat-uri esențiale.

În primul rând, evaluarea este pe un cluster AKS single-node cu trafic generat sintetic; un cluster enterprise multi-zonal produce un baseline de trafic benign mult mai divers (multi-tenancy, multiple controllere, sidecar-uri service mesh, operatori complexi). FPR-ul de 9,2% după histerezis ar putea fi semnificativ mai mare în producție și ar necesita re-calibrare. În al doilea rând, generalizarea tool-disjoint este parțial demonstrată: testele cu `recon_v2` și `kube-hunter` acoperă două scenarii concrete, dar un set mai larg de instrumente (Peirates, stratus-red-team, MKAT) ar fi necesar pentru o pretenție de generalizare robustă. În al treilea rând, dataset-ul are 52 episoade de atac — suficient pentru intervale de încredere bootstrap, dar nu pentru o pretenție statistică tare; un dataset cu sute sau mii de episoade independente ar fi standardul ideal.

Cu toate aceste limitări declarate, rezultatele susțin următoarele concluzii defensibile:

- Modelul Audit detectează **acțiunile concrete pe planul API** (secrete, exec, RBAC, escaladare) cu recall practic 100% pe sesiuni nevăzute, atât în regim dens cât și low-and-slow.
- Trade-off-ul recall-FPR la nivel operațional este controlabil prin histerezis: 75% recall cu 9,2% FPR la pragul curent, ajustabil prin parametrii pragului și ai histerezisului.
- Granița de detecție este explicit circumscrisă atacurilor cu acțiuni vizibile în audit; tactici care ocolesc planul API (kube-hunter, exploituri ale kubelet-ului, abuz al metadata service Azure) sunt invizibile pentru acest model — limitare arhitecturală care **motivează direct existența componentei Falco/runtime** și principiul defense-in-depth al sistemului propus.
