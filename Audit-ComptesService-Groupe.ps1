#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
================================================================================================
  SCRIPT      : Audit-ComptesService-Groupe.ps1
  AUTEUR      : Généré pour Hakim - ECN TENEXA / Mission Generali
  OBJECTIF    :
      Outil graphique (WinForms) permettant de :
        1. Rechercher les comptes de service dans l'Active Directory (par OU et/ou motif de nom)
        2. Vérifier si ces comptes appartiennent à un groupe AD cible
             -> Statut affiché en VERT  = membre du groupe
             -> Statut affiché en ROUGE = NON membre du groupe
        3. Sélectionner un ou plusieurs comptes (cases à cocher, sélection multiple)
        4. Corriger automatiquement (bouton "FIX") en ajoutant les comptes NON membres
           sélectionnés au groupe cible
        5. Exporter le résultat de l'analyse dans un fichier CSV horodaté

  SECURITE :
      - Mode SIMULATION activé par défaut (aucune écriture AD tant qu'il n'est pas décoché)
      - Confirmation obligatoire avant toute modification réelle (Add-ADGroupMember)
      - Assainissement (sanitize) de toutes les entrées utilisateur avant construction
        des filtres AD (anti-injection de filtre LDAP / PowerShell)
      - Journalisation complète (fichier log horodaté + zone de log dans l'IHM)
      - Support d'identifiants alternatifs (Get-Credential) si nécessaire
      - Aucune donnée sensible en clair, aucun mot de passe stocké
================================================================================================
#>

# ================================================================================================
# REGION 0 : INITIALISATION GENERALE
# ================================================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Vérification du module ActiveDirectory --------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Le module ActiveDirectory est introuvable sur ce poste.`nInstalle les RSAT (Remote Server Administration Tools) puis relance le script.",
        "Module manquant",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

# --- Configuration (modifiable) -----------------------------------------------------------------
$script:Config = [PSCustomObject]@{
    LogFolder        = Join-Path $env:USERPROFILE "Documents\Audit-ComptesService\Logs"
    CsvFolder        = Join-Path $env:USERPROFILE "Documents\Audit-ComptesService\Export"
    DefaultFilterPat = "svc_*"     # motif de nom par défaut pour repérer les comptes de service
}

foreach ($folder in @($script:Config.LogFolder, $script:Config.CsvFolder)) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
}

$script:LogFile        = Join-Path $script:Config.LogFolder ("Audit_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$script:Credential      = $null          # identifiants alternatifs (facultatif)
$script:TargetGroupDN   = $null          # DN du groupe cible sélectionné
$script:TargetGroupName = $null

# ================================================================================================
# REGION 1 : FONCTIONS UTILITAIRES
# ================================================================================================

function Write-Log {
    <#
        Écrit une ligne dans le fichier log ET dans la zone de log de l'IHM.
        Niveau : INFO / WARN / ERROR / ACTION
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","ACTION")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8

    if ($null -ne $script:txtLog) {
        $color = switch ($Level) {
            "ERROR"  { "Red" }
            "WARN"   { "DarkOrange" }
            "ACTION" { "Blue" }
            default  { "Black" }
        }
        $script:txtLog.SelectionStart  = $script:txtLog.TextLength
        $script:txtLog.SelectionLength = 0
        $script:txtLog.SelectionColor  = [System.Drawing.Color]::$color
        $script:txtLog.AppendText("$line`r`n")
        $script:txtLog.ScrollToCaret()
    }
}

function Get-SanitizedInput {
    <#
        Nettoie une chaîne saisie par l'utilisateur avant de l'utiliser dans un filtre AD.
        N'autorise que : lettres, chiffres, espace, - _ . * (utile pour les motifs de nom)
        -> Protection contre l'injection de filtre LDAP / PowerShell.
    #>
    param([string]$InputString)
    if ([string]::IsNullOrWhiteSpace($InputString)) { return "" }
    return ($InputString -replace '[^a-zA-Z0-9\séèêàçùû\-_\.\*]', '')
}

function Get-AdCredentialParams {
    <#
        Retourne une table de hashtable @{Credential=...} si des identifiants alternatifs
        ont été fournis, sinon une table vide (utilise le contexte de session en cours).
    #>
    if ($null -ne $script:Credential) {
        return @{ Credential = $script:Credential }
    }
    return @{}
}

# ================================================================================================
# REGION 2 : FONCTIONS METIER (RECHERCHE / ANALYSE / FIX / EXPORT)
# ================================================================================================

function Get-ServiceAccounts {
    <#
        Recherche les comptes de service dans l'AD.
        - $OuDn        : (optionnel) DN de l'OU dans laquelle restreindre la recherche
        - $NamePattern : motif de nom (ex: "svc_*") - utilisé avec -like
    #>
    param(
        [string]$OuDn,
        [string]$NamePattern
    )

    $cleanPattern = Get-SanitizedInput -InputString $NamePattern
    if ([string]::IsNullOrWhiteSpace($cleanPattern)) { $cleanPattern = "*" }

    $adParams = @{
        Filter     = { Name -like $cleanPattern }
        Properties = @("Name","SamAccountName","DisplayName","Enabled","MemberOf","DistinguishedName","Description")
        ErrorAction = "Stop"
    }
    $adParams += Get-AdCredentialParams

    if (-not [string]::IsNullOrWhiteSpace($OuDn)) {
        $adParams["SearchBase"] = $OuDn
    }

    try {
        Write-Log -Level INFO -Message "Recherche des comptes de service (motif='$cleanPattern', OU='$OuDn')"
        $results = Get-ADUser @adParams
        Write-Log -Level INFO -Message "Nombre de comptes trouvés : $($results.Count)"
        return $results
    }
    catch {
        Write-Log -Level ERROR -Message "Erreur lors de la recherche des comptes : $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Erreur lors de la recherche :`n$($_.Exception.Message)", "Erreur", "OK", "Error") | Out-Null
        return @()
    }
}

function Find-AdGroups {
    <#
        Recherche des groupes AD dont le nom contient le motif saisi (barre de recherche groupe).
    #>
    param([string]$NamePattern)

    $cleanPattern = Get-SanitizedInput -InputString $NamePattern
    if ([string]::IsNullOrWhiteSpace($cleanPattern)) { return @() }

    $adParams = @{
        Filter      = { Name -like "*$cleanPattern*" }
        Properties  = @("Name","DistinguishedName")
        ErrorAction = "Stop"
    }
    $adParams += Get-AdCredentialParams

    try {
        Write-Log -Level INFO -Message "Recherche de groupes (motif='$cleanPattern')"
        return Get-ADGroup @adParams | Sort-Object Name
    }
    catch {
        Write-Log -Level ERROR -Message "Erreur recherche groupe : $($_.Exception.Message)"
        return @()
    }
}

function Test-AccountGroupMembership {
    <#
        Vérifie, pour un compte AD donné (objet Get-ADUser avec MemberOf déjà chargé),
        s'il appartient au groupe cible ($script:TargetGroupDN).
        Retourne $true / $false.
    #>
    param($AdUser)

    if ([string]::IsNullOrWhiteSpace($script:TargetGroupDN)) { return $false }
    return ($AdUser.MemberOf -contains $script:TargetGroupDN)
}

function Add-AccountToTargetGroup {
    <#
        Ajoute un compte au groupe cible. Respecte le mode simulation.
    #>
    param([string]$SamAccountName)

    if ([string]::IsNullOrWhiteSpace($script:TargetGroupDN)) {
        throw "Aucun groupe cible sélectionné."
    }

    $adParams = @{
        Identity    = $script:TargetGroupDN
        Members     = $SamAccountName
        ErrorAction = "Stop"
    }
    $adParams += Get-AdCredentialParams

    if ($script:chkSimulation.Checked) {
        Write-Log -Level ACTION -Message "[SIMULATION] Ajout de '$SamAccountName' au groupe '$script:TargetGroupName' (aucune écriture réelle)"
        return $true
    }
    else {
        try {
            Add-ADGroupMember @adParams
            Write-Log -Level ACTION -Message "Compte '$SamAccountName' ajouté au groupe '$script:TargetGroupName'"
            return $true
        }
        catch {
            Write-Log -Level ERROR -Message "Échec ajout '$SamAccountName' : $($_.Exception.Message)"
            return $false
        }
    }
}

function Export-ResultsToCsv {
    param($DataTable)

    if ($DataTable.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Aucune donnée à exporter.", "Export CSV", "OK", "Information") | Out-Null
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.InitialDirectory = $script:Config.CsvFolder
    $saveDialog.FileName         = "Audit_ComptesService_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)
    $saveDialog.Filter           = "Fichier CSV (*.csv)|*.csv"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $DataTable | Select-Object SamAccountName, DisplayName, Enabled, Statut, ActionEffectuee, DateAnalyse |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8 -Delimiter ";"
            Write-Log -Level INFO -Message "Export CSV réalisé : $($saveDialog.FileName)"
            [System.Windows.Forms.MessageBox]::Show("Export terminé :`n$($saveDialog.FileName)", "Export CSV", "OK", "Information") | Out-Null
        }
        catch {
            Write-Log -Level ERROR -Message "Erreur export CSV : $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de l'export :`n$($_.Exception.Message)", "Erreur", "OK", "Error") | Out-Null
        }
    }
}

# ================================================================================================
# REGION 3 : CONSTRUCTION DE L'INTERFACE GRAPHIQUE (WinForms)
# ================================================================================================

# --- Fenêtre principale --------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Audit & Remédiation - Comptes de service / Appartenance à un groupe AD"
$form.Size            = New-Object System.Drawing.Size(1180, 800)
$form.StartPosition   = "CenterScreen"
$form.MinimumSize     = New-Object System.Drawing.Size(1000, 650)
$form.Font            = New-Object System.Drawing.Font("Segoe UI", 9)

# --- DataTable de travail (support du filtrage + de la grille) ----------------------------------
$script:dataTable = New-Object System.Data.DataTable
[void]$script:dataTable.Columns.Add("Select", [bool])
[void]$script:dataTable.Columns.Add("SamAccountName", [string])
[void]$script:dataTable.Columns.Add("DisplayName", [string])
[void]$script:dataTable.Columns.Add("Enabled", [string])
[void]$script:dataTable.Columns.Add("Statut", [string])          # "Non analysé" / "Membre" / "Non membre"
[void]$script:dataTable.Columns.Add("ActionEffectuee", [string])
[void]$script:dataTable.Columns.Add("DateAnalyse", [string])
[void]$script:dataTable.Columns.Add("DN", [string])                # colonne technique (masquée)

# ================================================================================================
# --- GROUPE 1 : Paramètres de recherche des comptes de service ----------------------------------
# ================================================================================================
$grpSearch = New-Object System.Windows.Forms.GroupBox
$grpSearch.Text     = "1. Recherche des comptes de service"
$grpSearch.Location = New-Object System.Drawing.Point(10, 10)
$grpSearch.Size     = New-Object System.Drawing.Size(1145, 90)

$lblOu = New-Object System.Windows.Forms.Label
$lblOu.Text = "OU (DN, optionnel) :"
$lblOu.Location = New-Object System.Drawing.Point(10, 25)
$lblOu.Size = New-Object System.Drawing.Size(120, 20)

$txtOu = New-Object System.Windows.Forms.TextBox
$txtOu.Location = New-Object System.Drawing.Point(135, 22)
$txtOu.Size = New-Object System.Drawing.Size(400, 20)
$txtOu.PlaceholderText = "Ex : OU=ComptesService,DC=domaine,DC=local"

$lblPattern = New-Object System.Windows.Forms.Label
$lblPattern.Text = "Motif de nom :"
$lblPattern.Location = New-Object System.Drawing.Point(545, 25)
$lblPattern.Size = New-Object System.Drawing.Size(90, 20)

$txtPattern = New-Object System.Windows.Forms.TextBox
$txtPattern.Location = New-Object System.Drawing.Point(635, 22)
$txtPattern.Size = New-Object System.Drawing.Size(150, 20)
$txtPattern.Text = $script:Config.DefaultFilterPat

$btnLoad = New-Object System.Windows.Forms.Button
$btnLoad.Text = "Charger les comptes"
$btnLoad.Location = New-Object System.Drawing.Point(800, 20)
$btnLoad.Size = New-Object System.Drawing.Size(150, 26)
$btnLoad.BackColor = [System.Drawing.Color]::LightSteelBlue

$chkAltCred = New-Object System.Windows.Forms.CheckBox
$chkAltCred.Text = "Utiliser des identifiants alternatifs"
$chkAltCred.Location = New-Object System.Drawing.Point(10, 55)
$chkAltCred.Size = New-Object System.Drawing.Size(220, 20)

$chkSimulation = New-Object System.Windows.Forms.CheckBox
$chkSimulation.Text = "Mode SIMULATION (aucune écriture AD)"
$chkSimulation.Location = New-Object System.Drawing.Point(260, 55)
$chkSimulation.Size = New-Object System.Drawing.Size(280, 20)
$chkSimulation.Checked = $true
$chkSimulation.ForeColor = [System.Drawing.Color]::DarkOrange
$script:chkSimulation = $chkSimulation

$grpSearch.Controls.AddRange(@($lblOu,$txtOu,$lblPattern,$txtPattern,$btnLoad,$chkAltCred,$chkSimulation))

# ================================================================================================
# --- GROUPE 2 : Barres de recherche (compte / groupe cible) -------------------------------------
# ================================================================================================
$grpFilters = New-Object System.Windows.Forms.GroupBox
$grpFilters.Text = "2. Recherche compte affiché / Sélection du groupe cible"
$grpFilters.Location = New-Object System.Drawing.Point(10, 105)
$grpFilters.Size = New-Object System.Drawing.Size(1145, 90)

$lblSearchAccount = New-Object System.Windows.Forms.Label
$lblSearchAccount.Text = "Rechercher un compte :"
$lblSearchAccount.Location = New-Object System.Drawing.Point(10, 25)
$lblSearchAccount.Size = New-Object System.Drawing.Size(130, 20)

$txtSearchAccount = New-Object System.Windows.Forms.TextBox
$txtSearchAccount.Location = New-Object System.Drawing.Point(145, 22)
$txtSearchAccount.Size = New-Object System.Drawing.Size(250, 20)
$txtSearchAccount.PlaceholderText = "Filtrer la liste affichée..."

$lblGroupSearch = New-Object System.Windows.Forms.Label
$lblGroupSearch.Text = "Rechercher un groupe :"
$lblGroupSearch.Location = New-Object System.Drawing.Point(420, 25)
$lblGroupSearch.Size = New-Object System.Drawing.Size(130, 20)

$txtGroupSearch = New-Object System.Windows.Forms.TextBox
$txtGroupSearch.Location = New-Object System.Drawing.Point(555, 22)
$txtGroupSearch.Size = New-Object System.Drawing.Size(220, 20)

$btnGroupSearch = New-Object System.Windows.Forms.Button
$btnGroupSearch.Text = "Rechercher"
$btnGroupSearch.Location = New-Object System.Drawing.Point(785, 20)
$btnGroupSearch.Size = New-Object System.Drawing.Size(90, 24)

$cmbGroupResults = New-Object System.Windows.Forms.ComboBox
$cmbGroupResults.Location = New-Object System.Drawing.Point(10, 55)
$cmbGroupResults.Size = New-Object System.Drawing.Size(500, 22)
$cmbGroupResults.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList

$lblGroupSelected = New-Object System.Windows.Forms.Label
$lblGroupSelected.Text = "Aucun groupe sélectionné"
$lblGroupSelected.Location = New-Object System.Drawing.Point(520, 58)
$lblGroupSelected.Size = New-Object System.Drawing.Size(600, 20)
$lblGroupSelected.ForeColor = [System.Drawing.Color]::DarkRed
$lblGroupSelected.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$grpFilters.Controls.AddRange(@($lblSearchAccount,$txtSearchAccount,$lblGroupSearch,$txtGroupSearch,$btnGroupSearch,$cmbGroupResults,$lblGroupSelected))

# ================================================================================================
# --- GROUPE 3 : Grille de résultats --------------------------------------------------------------
# ================================================================================================
$dgv = New-Object System.Windows.Forms.DataGridView
$dgv.Location = New-Object System.Drawing.Point(10, 205)
$dgv.Size = New-Object System.Drawing.Size(1145, 430)
$dgv.Anchor = "Top,Bottom,Left,Right"
$dgv.AutoGenerateColumns = $false
$dgv.AllowUserToAddRows = $false
$dgv.AllowUserToDeleteRows = $false
$dgv.SelectionMode = "FullRowSelect"
$dgv.RowHeadersVisible = $false
$dgv.ReadOnly = $false
$dgv.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill

# Colonnes explicites (liées au DataTable)
$colSelect = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colSelect.DataPropertyName = "Select"
$colSelect.HeaderText = "Sélection"
$colSelect.Width = 70
$colSelect.FillWeight = 8

$colSam = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSam.DataPropertyName = "SamAccountName"
$colSam.HeaderText = "SamAccountName"
$colSam.ReadOnly = $true
$colSam.FillWeight = 20

$colDisplay = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDisplay.DataPropertyName = "DisplayName"
$colDisplay.HeaderText = "Nom affiché"
$colDisplay.ReadOnly = $true
$colDisplay.FillWeight = 25

$colEnabled = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colEnabled.DataPropertyName = "Enabled"
$colEnabled.HeaderText = "Activé"
$colEnabled.ReadOnly = $true
$colEnabled.FillWeight = 10

$colStatut = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatut.DataPropertyName = "Statut"
$colStatut.HeaderText = "Statut (appartenance au groupe)"
$colStatut.ReadOnly = $true
$colStatut.FillWeight = 22

$colAction = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAction.DataPropertyName = "ActionEffectuee"
$colAction.HeaderText = "Action effectuée"
$colAction.ReadOnly = $true
$colAction.FillWeight = 15

$dgv.Columns.AddRange(@($colSelect,$colSam,$colDisplay,$colEnabled,$colStatut,$colAction))

# ================================================================================================
# --- GROUPE 4 : Boutons d'action -----------------------------------------------------------------
# ================================================================================================
$pnlActions = New-Object System.Windows.Forms.Panel
$pnlActions.Location = New-Object System.Drawing.Point(10, 645)
$pnlActions.Size = New-Object System.Drawing.Size(1145, 40)
$pnlActions.Anchor = "Bottom,Left,Right"

$btnCheckAll = New-Object System.Windows.Forms.Button
$btnCheckAll.Text = "Tout cocher"
$btnCheckAll.Location = New-Object System.Drawing.Point(0, 5)
$btnCheckAll.Size = New-Object System.Drawing.Size(110, 28)

$btnUncheckAll = New-Object System.Windows.Forms.Button
$btnUncheckAll.Text = "Tout décocher"
$btnUncheckAll.Location = New-Object System.Drawing.Point(115, 5)
$btnUncheckAll.Size = New-Object System.Drawing.Size(110, 28)

$btnCheckNonMembers = New-Object System.Windows.Forms.Button
$btnCheckNonMembers.Text = "Cocher les non-membres"
$btnCheckNonMembers.Location = New-Object System.Drawing.Point(230, 5)
$btnCheckNonMembers.Size = New-Object System.Drawing.Size(160, 28)

$btnAnalyze = New-Object System.Windows.Forms.Button
$btnAnalyze.Text = "Analyser l'appartenance"
$btnAnalyze.Location = New-Object System.Drawing.Point(400, 5)
$btnAnalyze.Size = New-Object System.Drawing.Size(170, 28)
$btnAnalyze.BackColor = [System.Drawing.Color]::LightYellow

$btnFix = New-Object System.Windows.Forms.Button
$btnFix.Text = "FIX - Ajouter au groupe"
$btnFix.Location = New-Object System.Drawing.Point(580, 5)
$btnFix.Size = New-Object System.Drawing.Size(170, 28)
$btnFix.BackColor = [System.Drawing.Color]::LightGreen

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Exporter CSV"
$btnExport.Location = New-Object System.Drawing.Point(760, 5)
$btnExport.Size = New-Object System.Drawing.Size(140, 28)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(910, 8)
$progressBar.Size = New-Object System.Drawing.Size(235, 22)
$progressBar.Style = "Continuous"

$pnlActions.Controls.AddRange(@($btnCheckAll,$btnUncheckAll,$btnCheckNonMembers,$btnAnalyze,$btnFix,$btnExport,$progressBar))

# ================================================================================================
# --- GROUPE 5 : Zone de journal (log) ------------------------------------------------------------
# ================================================================================================
$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Location = New-Object System.Drawing.Point(10, 690)
$txtLog.Size = New-Object System.Drawing.Size(1145, 65)
$txtLog.Anchor = "Bottom,Left,Right"
$txtLog.ReadOnly = $true
$txtLog.BackColor = [System.Drawing.Color]::White
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 8)
$script:txtLog = $txtLog

# --- Ajout de tous les contrôles au formulaire ---------------------------------------------------
$form.Controls.AddRange(@($grpSearch,$grpFilters,$dgv,$pnlActions,$txtLog))

# ================================================================================================
# REGION 4 : MISE EN FORME CONDITIONNELLE DE LA GRILLE (VERT / ROUGE)
# ================================================================================================
$dgv.Add_CellFormatting({
    param($sender, $e)
    if ($dgv.Columns[$e.ColumnIndex].DataPropertyName -eq "Statut") {
        switch ($e.Value) {
            "Membre"     { $e.CellStyle.BackColor = [System.Drawing.Color]::LightGreen; $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGreen }
            "Non membre" { $e.CellStyle.BackColor = [System.Drawing.Color]::LightSalmon; $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed }
            default      { $e.CellStyle.BackColor = [System.Drawing.Color]::WhiteSmoke;  $e.CellStyle.ForeColor = [System.Drawing.Color]::Gray }
        }
    }
})

# ================================================================================================
# REGION 5 : EVENEMENTS DE L'INTERFACE
# ================================================================================================

# --- Identifiants alternatifs ---------------------------------------------------------------------
$chkAltCred.Add_CheckedChanged({
    if ($chkAltCred.Checked) {
        $cred = Get-Credential -Message "Identifiants pour les opérations Active Directory"
        if ($null -ne $cred) {
            $script:Credential = $cred
            Write-Log -Level INFO -Message "Identifiants alternatifs définis pour l'utilisateur : $($cred.UserName)"
        }
        else {
            $chkAltCred.Checked = $false
        }
    }
    else {
        $script:Credential = $null
        Write-Log -Level INFO -Message "Retour au contexte de session courant (identifiants alternatifs désactivés)"
    }
})

# --- Chargement des comptes de service --------------------------------------------------------
$btnLoad.Add_Click({
    $dgv.DataSource = $null
    $script:dataTable.Rows.Clear()
    $progressBar.Style = "Marquee"

    $accounts = Get-ServiceAccounts -OuDn $txtOu.Text.Trim() -NamePattern $txtPattern.Text.Trim()

    foreach ($acc in $accounts) {
        $row = $script:dataTable.NewRow()
        $row["Select"]          = $false
        $row["SamAccountName"]  = $acc.SamAccountName
        $row["DisplayName"]     = if ($acc.DisplayName) { $acc.DisplayName } else { $acc.Name }
        $row["Enabled"]         = if ($acc.Enabled) { "Oui" } else { "Non" }
        $row["Statut"]          = "Non analysé"
        $row["ActionEffectuee"] = ""
        $row["DateAnalyse"]     = ""
        $row["DN"]              = $acc.DistinguishedName
        $script:dataTable.Rows.Add($row)
    }

    $view = New-Object System.Data.DataView($script:dataTable)
    $dgv.DataSource = $view

    $progressBar.Style = "Continuous"
    Write-Log -Level INFO -Message "$($accounts.Count) compte(s) de service chargé(s) dans la grille"
})

# --- Filtrage en direct de la grille (recherche de compte) -------------------------------------
$txtSearchAccount.Add_TextChanged({
    $clean = (Get-SanitizedInput -InputString $txtSearchAccount.Text) -replace "'", "''"
    try {
        if ([string]::IsNullOrWhiteSpace($clean)) {
            $script:dataTable.DefaultView.RowFilter = ""
        }
        else {
            $script:dataTable.DefaultView.RowFilter = "SamAccountName LIKE '%$clean%' OR DisplayName LIKE '%$clean%'"
        }
    }
    catch { }
})

# --- Recherche de groupe (barre de recherche groupe) --------------------------------------------
$btnGroupSearch.Add_Click({
    $cmbGroupResults.Items.Clear()
    $groups = Find-AdGroups -NamePattern $txtGroupSearch.Text.Trim()

    if ($groups.Count -eq 0) {
        Write-Log -Level WARN -Message "Aucun groupe trouvé pour le motif '$($txtGroupSearch.Text)'"
    }

    foreach ($g in $groups) {
        [void]$cmbGroupResults.Items.Add($g)
    }
    $cmbGroupResults.DisplayMember = "Name"

    if ($cmbGroupResults.Items.Count -gt 0) {
        $cmbGroupResults.SelectedIndex = 0
    }
})

$cmbGroupResults.Add_SelectedIndexChanged({
    if ($cmbGroupResults.SelectedItem) {
        $script:TargetGroupDN   = $cmbGroupResults.SelectedItem.DistinguishedName
        $script:TargetGroupName = $cmbGroupResults.SelectedItem.Name
        $lblGroupSelected.Text = "Groupe cible : $($script:TargetGroupName)"
        $lblGroupSelected.ForeColor = [System.Drawing.Color]::DarkGreen
        Write-Log -Level INFO -Message "Groupe cible sélectionné : $($script:TargetGroupName) ($($script:TargetGroupDN))"
    }
})

# --- Cocher / décocher tout ----------------------------------------------------------------------
$btnCheckAll.Add_Click({
    foreach ($row in $script:dataTable.Rows) { $row["Select"] = $true }
    $dgv.Refresh()
})
$btnUncheckAll.Add_Click({
    foreach ($row in $script:dataTable.Rows) { $row["Select"] = $false }
    $dgv.Refresh()
})
$btnCheckNonMembers.Add_Click({
    foreach ($row in $script:dataTable.Rows) {
        if ($row["Statut"] -eq "Non membre") { $row["Select"] = $true }
    }
    $dgv.Refresh()
})

# --- Analyse d'appartenance au groupe -------------------------------------------------------------
$btnAnalyze.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:TargetGroupDN)) {
        [System.Windows.Forms.MessageBox]::Show("Sélectionne d'abord un groupe cible (barre de recherche groupe).", "Groupe manquant", "OK", "Warning") | Out-Null
        return
    }
    if ($script:dataTable.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Aucun compte chargé. Clique d'abord sur 'Charger les comptes'.", "Aucune donnée", "OK", "Warning") | Out-Null
        return
    }

    $progressBar.Style = "Continuous"
    $progressBar.Maximum = $script:dataTable.Rows.Count
    $progressBar.Value = 0

    $adParams = @{ Properties = @("MemberOf"); ErrorAction = "SilentlyContinue" }
    $adParams += Get-AdCredentialParams

    foreach ($row in $script:dataTable.Rows) {
        try {
            $adUser = Get-ADUser -Identity $row["SamAccountName"] @adParams
            $isMember = Test-AccountGroupMembership -AdUser $adUser
            $row["Statut"] = if ($isMember) { "Membre" } else { "Non membre" }
            $row["DateAnalyse"] = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        catch {
            $row["Statut"] = "Erreur"
            Write-Log -Level ERROR -Message "Erreur analyse '$($row['SamAccountName'])' : $($_.Exception.Message)"
        }
        $progressBar.Value = [Math]::Min($progressBar.Value + 1, $progressBar.Maximum)
        [System.Windows.Forms.Application]::DoEvents()
    }

    $dgv.Refresh()
    $membres    = ($script:dataTable.Rows | Where-Object { $_["Statut"] -eq "Membre" }).Count
    $nonMembres = ($script:dataTable.Rows | Where-Object { $_["Statut"] -eq "Non membre" }).Count
    Write-Log -Level INFO -Message "Analyse terminée : $membres membre(s) / $nonMembres non-membre(s)"
})

# --- FIX : ajout des comptes sélectionnés et non-membres au groupe -------------------------------
$btnFix.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:TargetGroupDN)) {
        [System.Windows.Forms.MessageBox]::Show("Sélectionne d'abord un groupe cible.", "Groupe manquant", "OK", "Warning") | Out-Null
        return
    }

    $toFix = $script:dataTable.Rows | Where-Object { $_["Select"] -eq $true -and $_["Statut"] -eq "Non membre" }

    if ($toFix.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Aucun compte sélectionné et non-membre à corriger.`n(Coche les comptes en rouge, ou utilise 'Cocher les non-membres'.)", "Rien à corriger", "OK", "Information") | Out-Null
        return
    }

    $listNames = ($toFix | ForEach-Object { $_["SamAccountName"] }) -join "`n"
    $modeTxt = if ($chkSimulation.Checked) { "MODE SIMULATION (aucune écriture réelle)" } else { "MODE REEL - ECRITURE DANS L'ANNUAIRE" }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Tu es sur le point d'ajouter $($toFix.Count) compte(s) au groupe '$script:TargetGroupName' :`n`n$listNames`n`n$modeTxt`n`nConfirmer l'opération ?",
        "Confirmation - Ajout au groupe",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log -Level INFO -Message "Opération FIX annulée par l'utilisateur"
        return
    }

    $progressBar.Maximum = $toFix.Count
    $progressBar.Value = 0

    foreach ($row in $toFix) {
        $ok = Add-AccountToTargetGroup -SamAccountName $row["SamAccountName"]
        if ($ok) {
            $row["Statut"]          = if ($chkSimulation.Checked) { "Non membre" } else { "Membre" }
            $row["ActionEffectuee"] = if ($chkSimulation.Checked) { "Simulé" } else { "Ajouté le $(Get-Date -Format 'yyyy-MM-dd HH:mm')" }
        }
        else {
            $row["ActionEffectuee"] = "Échec"
        }
        $progressBar.Value = [Math]::Min($progressBar.Value + 1, $progressBar.Maximum)
        [System.Windows.Forms.Application]::DoEvents()
    }

    $dgv.Refresh()
    Write-Log -Level INFO -Message "Opération FIX terminée sur $($toFix.Count) compte(s)"
})

# --- Export CSV -----------------------------------------------------------------------------------
$btnExport.Add_Click({
    Export-ResultsToCsv -DataTable $script:dataTable
})

# ================================================================================================
# REGION 6 : LANCEMENT DE L'APPLICATION
# ================================================================================================
Write-Log -Level INFO -Message "=== Démarrage de l'outil d'audit des comptes de service ==="
Write-Log -Level INFO -Message "Fichier de log : $script:LogFile"
[void]$form.ShowDialog()
Write-Log -Level INFO -Message "=== Fermeture de l'outil ==="
