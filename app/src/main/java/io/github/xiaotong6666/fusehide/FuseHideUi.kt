/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("ktlint:standard:function-naming")

package io.github.xiaotong6666.fusehide

import android.view.HapticFeedbackConstants
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Checkbox
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TabRowWithContour
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.util.Locale

@Composable
fun FuseHideHomeScreen(
    selectedTab: Int,
    onTabSelected: (Int) -> Unit,
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    configStatusText: String,
    lastAckTokenText: String,
    lastAckResultText: String,
    lastApplyTimeText: String,
    draftVsAppliedDiff: HideConfigDiff,
    appliedConfigSnapshotText: String,
    highlightConfigResults: Boolean,
    configResultsScrollToken: Int,
    enableHideAllRootEntries: Boolean,
    hideAllRootEntriesExemptionsText: String,
    hiddenTargetsText: String,
    hiddenPackagesText: String,
    pathText: String,
    pathText2: String,
    outputText: String,
    onStatusClick: () -> Unit,
    onEnableHideAllRootEntriesChanged: (Boolean) -> Unit,
    onHideAllRootEntriesExemptionsChanged: (String) -> Unit,
    onHiddenTargetsChanged: (String) -> Unit,
    onHiddenPackagesChanged: (String) -> Unit,
    onSaveConfigClick: () -> Unit,
    onApplyConfigClick: () -> Unit,
    onResetConfigClick: () -> Unit,
    onRefreshAppliedConfigClick: () -> Unit,
    onPathChanged: (String) -> Unit,
    onPath2Changed: (String) -> Unit,
    onStatClick: () -> Unit,
    onAccessClick: () -> Unit,
    onListClick: () -> Unit,
    onOpenClick: () -> Unit,
    onGetConClick: () -> Unit,
    onCreateClick: () -> Unit,
    onMkdirClick: () -> Unit,
    onMoveClick: () -> Unit,
    onRmdirClick: () -> Unit,
    onUnlinkClick: () -> Unit,
    onAllPkgClick: () -> Unit,
    onInsertZwjClick: () -> Unit,
    onClearClick: () -> Unit,
    onResetClick: () -> Unit,
    onCopyAllClick: () -> Unit,
    onSelfDataClick: () -> Unit,
) {
    val view = LocalView.current
    val pagerState = rememberPagerState(initialPage = selectedTab, pageCount = { 2 })
    val coroutineScope = rememberCoroutineScope()
    val scrollBehavior = MiuixScrollBehavior()

    LaunchedEffect(selectedTab) {
        if (pagerState.currentPage != selectedTab) {
            pagerState.animateScrollToPage(selectedTab)
        }
    }

    LaunchedEffect(pagerState.currentPage) {
        if (pagerState.currentPage != selectedTab) {
            onTabSelected(pagerState.currentPage)
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize().nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = stringResource(R.string.app_name),
                color = MiuixTheme.colorScheme.surface,
                titleColor = MiuixTheme.colorScheme.onSurface,
                scrollBehavior = scrollBehavior,
                subtitle = if (selectedTab == 0) {
                    stringResource(R.string.home_subtitle_policy)
                } else {
                    stringResource(R.string.home_subtitle_probe)
                },
                subtitleColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                bottomContent = {
                    TabRowWithContour(
                        tabs = listOf(
                            stringResource(R.string.tab_policy),
                            stringResource(R.string.tab_probe),
                        ),
                        selectedTabIndex = selectedTab,
                        onTabSelected = {
                            view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                            onTabSelected(it)
                            coroutineScope.launch { pagerState.animateScrollToPage(it) }
                        },
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                },
            )
        },
    ) { paddingValues ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.fillMaxSize(),
        ) { page ->
            when (page) {
                0 -> ConfigScreen(
                    infoText = infoText,
                    statusText = statusText,
                    isHooked = isHooked,
                    hookedPackage = hookedPackage,
                    hookedPid = hookedPid,
                    hookCheckCompleted = hookCheckCompleted,
                    configStatusText = configStatusText,
                    lastAckTokenText = lastAckTokenText,
                    lastAckResultText = lastAckResultText,
                    lastApplyTimeText = lastApplyTimeText,
                    draftVsAppliedDiff = draftVsAppliedDiff,
                    appliedConfigSnapshotText = appliedConfigSnapshotText,
                    highlightConfigResults = highlightConfigResults,
                    configResultsScrollToken = configResultsScrollToken,
                    enableHideAllRootEntries = enableHideAllRootEntries,
                    hideAllRootEntriesExemptionsText = hideAllRootEntriesExemptionsText,
                    hiddenTargetsText = hiddenTargetsText,
                    hiddenPackagesText = hiddenPackagesText,
                    onStatusClick = onStatusClick,
                    onEnableHideAllRootEntriesChanged = onEnableHideAllRootEntriesChanged,
                    onHideAllRootEntriesExemptionsChanged = onHideAllRootEntriesExemptionsChanged,
                    onHiddenTargetsChanged = onHiddenTargetsChanged,
                    onHiddenPackagesChanged = onHiddenPackagesChanged,
                    onSaveConfigClick = onSaveConfigClick,
                    onApplyConfigClick = onApplyConfigClick,
                    onResetConfigClick = onResetConfigClick,
                    onRefreshAppliedConfigClick = { onRefreshAppliedConfigClick() },
                    contentPadding = paddingValues,
                )

                else -> DebugScreen(
                    infoText = infoText,
                    statusText = statusText,
                    isHooked = isHooked,
                    hookedPackage = hookedPackage,
                    hookedPid = hookedPid,
                    hookCheckCompleted = hookCheckCompleted,
                    pathText = pathText,
                    pathText2 = pathText2,
                    outputText = outputText,
                    onStatusClick = onStatusClick,
                    onPathChanged = onPathChanged,
                    onPath2Changed = onPath2Changed,
                    onStatClick = onStatClick,
                    onAccessClick = onAccessClick,
                    onListClick = onListClick,
                    onOpenClick = onOpenClick,
                    onGetConClick = onGetConClick,
                    onCreateClick = onCreateClick,
                    onMkdirClick = onMkdirClick,
                    onMoveClick = onMoveClick,
                    onRmdirClick = onRmdirClick,
                    onUnlinkClick = onUnlinkClick,
                    onAllPkgClick = onAllPkgClick,
                    onInsertZwjClick = onInsertZwjClick,
                    onClearClick = onClearClick,
                    onResetClick = onResetClick,
                    onCopyAllClick = onCopyAllClick,
                    onSelfDataClick = onSelfDataClick,
                    contentPadding = paddingValues,
                )
            }
        }
    }
}

@Composable
private fun ConfigScreen(
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    configStatusText: String,
    lastAckTokenText: String,
    lastAckResultText: String,
    lastApplyTimeText: String,
    draftVsAppliedDiff: HideConfigDiff,
    appliedConfigSnapshotText: String,
    highlightConfigResults: Boolean,
    configResultsScrollToken: Int,
    enableHideAllRootEntries: Boolean,
    hideAllRootEntriesExemptionsText: String,
    hiddenTargetsText: String,
    hiddenPackagesText: String,
    onStatusClick: () -> Unit,
    onEnableHideAllRootEntriesChanged: (Boolean) -> Unit,
    onHideAllRootEntriesExemptionsChanged: (String) -> Unit,
    onHiddenTargetsChanged: (String) -> Unit,
    onHiddenPackagesChanged: (String) -> Unit,
    onSaveConfigClick: () -> Unit,
    onApplyConfigClick: () -> Unit,
    onResetConfigClick: () -> Unit,
    onRefreshAppliedConfigClick: () -> Unit,
    contentPadding: PaddingValues,
) {
    val view = LocalView.current
    val scrollState = rememberScrollState()
    var showDetailedDiff by remember { mutableStateOf(false) }
    var showAppliedSnapshot by remember { mutableStateOf(false) }
    val resultsNeedAttention = highlightConfigResults || draftVsAppliedDiff.hasDifferences

    LaunchedEffect(configResultsScrollToken) {
        if (configResultsScrollToken > 0) {
            scrollState.animateScrollTo(scrollState.maxValue)
        }
    }

    LaunchedEffect(highlightConfigResults, draftVsAppliedDiff.hasDifferences) {
        if (highlightConfigResults || draftVsAppliedDiff.hasDifferences) {
            showAppliedSnapshot = true
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(contentPadding)
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SectionCard {
            Text(
                stringResource(R.string.section_runtime_policy),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.section_runtime_policy_desc),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                StatusChip(
                    modifier = Modifier.weight(1f).heightIn(min = 130.dp),
                    label = stringResource(R.string.label_hook),
                    value = hookSummaryValue(isHooked = isHooked, hookCheckCompleted = hookCheckCompleted),
                    supportingText = hookSummarySupportingText(
                        isHooked = isHooked,
                        hookCheckCompleted = hookCheckCompleted,
                        hookedPackage = hookedPackage,
                    ),
                    metaText = hookSummaryMetaText(isHooked = isHooked, hookedPid = hookedPid),
                    emphasized = isHooked,
                    onClick = onStatusClick,
                )
                StatusChip(
                    modifier = Modifier.weight(1f).heightIn(min = 130.dp),
                    label = stringResource(R.string.label_sync),
                    value = if (resultsNeedAttention) stringResource(R.string.state_sync_needs_review) else stringResource(R.string.state_sync_ok),
                    emphasized = !resultsNeedAttention,
                )
            }
            Spacer(Modifier.height(10.dp))
            InfoPanel(title = stringResource(R.string.label_device), text = infoText, monospace = true)
        }

        SectionCard {
            Text(
                stringResource(R.string.section_editable_draft),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.section_editable_draft_desc),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Card(
                onClick = {
                    view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                    onEnableHideAllRootEntriesChanged(!enableHideAllRootEntries)
                },
                colors = CardDefaults.defaultColors(
                    color = MiuixTheme.colorScheme.surfaceContainerHighest,
                    contentColor = MiuixTheme.colorScheme.onSurfaceContainerHighest,
                ),
                insideMargin = PaddingValues(0.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = androidx.compose.ui.Alignment.Top,
                ) {
                    Checkbox(
                        state = if (enableHideAllRootEntries) ToggleableState.On else ToggleableState.Off,
                        onClick = {
                            view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                            onEnableHideAllRootEntriesChanged(!enableHideAllRootEntries)
                        },
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.field_hide_all_title), style = MiuixTheme.textStyles.headline2)
                        Text(
                            text = stringResource(R.string.field_hide_all_desc),
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            TextField(
                value = hideAllRootEntriesExemptionsText,
                onValueChange = onHideAllRootEntriesExemptionsChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_visible_exemptions),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurfaceSecondary),
                minLines = 5,
                maxLines = 5,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_visible_exemptions_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = hiddenTargetsText,
                onValueChange = onHiddenTargetsChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_hidden_targets),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurfaceSecondary),
                minLines = 5,
                maxLines = 5,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_hidden_targets_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = hiddenPackagesText,
                onValueChange = onHiddenPackagesChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_hidden_package_names),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurfaceSecondary),
                minLines = 5,
                maxLines = 5,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_hidden_package_names_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(14.dp))
            DualActionRow(
                primaryLabel = stringResource(R.string.button_apply),
                onPrimaryClick = onApplyConfigClick,
                secondaryLabel = stringResource(R.string.button_save),
                onSecondaryClick = onSaveConfigClick,
            )
            Spacer(Modifier.height(8.dp))
            DualActionRow(
                primaryLabel = stringResource(R.string.button_refresh_applied),
                onPrimaryClick = onRefreshAppliedConfigClick,
                secondaryLabel = stringResource(R.string.button_restore_defaults),
                onSecondaryClick = onResetConfigClick,
                primaryFilled = false,
            )
        }

        SectionCard {
            Text(
                stringResource(R.string.section_apply_feedback),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = androidx.compose.ui.Alignment.Top,
            ) {
                MetricCard(stringResource(R.string.label_last_ack), lastAckResultText, Modifier.weight(1f))
                MetricCard(stringResource(R.string.label_applied_at), lastApplyTimeText, Modifier.weight(1f))
            }
            Spacer(Modifier.height(10.dp))
            InfoPanel(
                title = stringResource(R.string.label_last_token),
                text = lastAckTokenText,
                monospace = true,
            )
            Spacer(Modifier.height(10.dp))
            InfoPanel(
                title = if (resultsNeedAttention) stringResource(R.string.label_attention) else stringResource(R.string.label_status),
                text = configStatusText.ifEmpty { draftVsAppliedDiff.summary },
                emphasized = resultsNeedAttention,
            )
            Spacer(Modifier.height(8.dp))
            InfoPanel(
                title = stringResource(R.string.label_draft_vs_applied),
                text = draftVsAppliedDiff.summary,
                emphasized = draftVsAppliedDiff.hasDifferences,
            )
        }
        if (draftVsAppliedDiff.hasDifferences) {
            SectionCard {
                Text(
                    stringResource(R.string.section_detailed_diff),
                    style = MiuixTheme.textStyles.title4,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(6.dp))
                TextButton(
                    text = if (showDetailedDiff) stringResource(R.string.button_hide_detailed_diff) else stringResource(R.string.button_show_detailed_diff),
                    onClick = { showDetailedDiff = !showDetailedDiff },
                )
                if (showDetailedDiff) {
                    Spacer(Modifier.height(6.dp))
                    InfoPanel(
                        title = stringResource(R.string.label_draft_vs_applied),
                        text = draftVsAppliedDiff.details,
                        monospace = true,
                    )
                }
            }
        }

        SectionCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        stringResource(R.string.section_snapshot),
                        style = MiuixTheme.textStyles.title4,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.section_snapshot_desc),
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                TextButton(
                    text = if (showAppliedSnapshot) stringResource(R.string.button_hide) else stringResource(R.string.button_show),
                    onClick = {
                        view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
                        showAppliedSnapshot = !showAppliedSnapshot
                    },
                )
            }
            if (showAppliedSnapshot) {
                Spacer(Modifier.height(10.dp))
                InfoPanel(
                    title = stringResource(R.string.label_current_native_config),
                    text = appliedConfigSnapshotText,
                    monospace = true,
                    emphasized = resultsNeedAttention,
                )
            }
        }
    }
}

@Composable
private fun DebugScreen(
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    pathText: String,
    pathText2: String,
    outputText: String,
    onStatusClick: () -> Unit,
    onPathChanged: (String) -> Unit,
    onPath2Changed: (String) -> Unit,
    onStatClick: () -> Unit,
    onAccessClick: () -> Unit,
    onListClick: () -> Unit,
    onOpenClick: () -> Unit,
    onGetConClick: () -> Unit,
    onCreateClick: () -> Unit,
    onMkdirClick: () -> Unit,
    onMoveClick: () -> Unit,
    onRmdirClick: () -> Unit,
    onUnlinkClick: () -> Unit,
    onAllPkgClick: () -> Unit,
    onInsertZwjClick: () -> Unit,
    onClearClick: () -> Unit,
    onResetClick: () -> Unit,
    onCopyAllClick: () -> Unit,
    onSelfDataClick: () -> Unit,
    contentPadding: PaddingValues,
) {
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(contentPadding)
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SectionCard {
            Text(
                stringResource(R.string.section_probe_target),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.section_probe_target_desc),
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                StatusChip(
                    modifier = Modifier.weight(1f),
                    label = stringResource(R.string.label_hook),
                    value = hookSummaryValue(isHooked = isHooked, hookCheckCompleted = hookCheckCompleted),
                    supportingText = hookSummarySupportingText(
                        isHooked = isHooked,
                        hookCheckCompleted = hookCheckCompleted,
                        hookedPackage = hookedPackage,
                    ),
                    metaText = hookSummaryMetaText(isHooked = isHooked, hookedPid = hookedPid),
                    emphasized = isHooked,
                    onClick = onStatusClick,
                )
            }
            Spacer(Modifier.height(10.dp))
            InfoPanel(
                title = stringResource(R.string.label_path),
                text = pathText.ifBlank { "-" },
                monospace = true,
            )
            Spacer(Modifier.height(10.dp))
            InfoPanel(title = stringResource(R.string.label_device), text = infoText, monospace = true)
        }

        SectionCard {
            Text(
                stringResource(R.string.section_paths),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            TextField(
                value = pathText,
                onValueChange = onPathChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.label_primary_path),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                singleLine = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_primary_path_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = pathText2,
                onValueChange = onPath2Changed,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.label_secondary_path),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                singleLine = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_secondary_path_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }

        SectionCard {
            Text(
                stringResource(R.string.section_common_probes),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            ActionGrid(
                listOf(
                    GridActionItem(stringResource(R.string.button_stat), onStatClick),
                    GridActionItem(stringResource(R.string.button_access), onAccessClick),
                    GridActionItem(stringResource(R.string.button_list), onListClick),
                    GridActionItem(stringResource(R.string.button_open), onOpenClick),
                ),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.section_mutation_probes),
                style = MiuixTheme.textStyles.title4.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            ActionGrid(
                listOf(
                    GridActionItem(stringResource(R.string.button_get_con), onGetConClick),
                    GridActionItem(stringResource(R.string.button_create), onCreateClick),
                    GridActionItem(stringResource(R.string.button_mkdir), onMkdirClick),
                    GridActionItem(stringResource(R.string.button_rename_move), onMoveClick),
                    GridActionItem(stringResource(R.string.button_rmdir), onRmdirClick, isError = true),
                    GridActionItem(stringResource(R.string.button_unlink), onUnlinkClick),
                ),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.section_utilities),
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            ActionGrid(
                listOf(
                    GridActionItem(stringResource(R.string.button_all_pkg), onAllPkgClick),
                    GridActionItem(stringResource(R.string.button_insert_zwj), onInsertZwjClick),
                    GridActionItem(stringResource(R.string.button_clear_output), onClearClick),
                    GridActionItem(stringResource(R.string.button_reset_path), onResetClick),
                    GridActionItem(stringResource(R.string.button_copy_output), onCopyAllClick),
                    GridActionItem(stringResource(R.string.button_self_data), onSelfDataClick),
                ),
            )
        }

        SectionCard {
            Text(
                stringResource(R.string.section_probe_output),
                style = MiuixTheme.textStyles.title4.copy(fontWeight = FontWeight.Medium),
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            InfoPanel(
                title = stringResource(R.string.label_runtime_output),
                text = outputText.ifEmpty { stringResource(R.string.probe_output_empty) },
                monospace = true,
            )
        }
    }
}

@Composable
private fun DualActionRow(
    primaryLabel: String,
    onPrimaryClick: () -> Unit,
    secondaryLabel: String,
    onSecondaryClick: () -> Unit,
    primaryFilled: Boolean = true,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (primaryFilled) {
            Button(
                onClick = onPrimaryClick,
                modifier = Modifier.weight(1f).height(56.dp),
                colors = ButtonDefaults.buttonColorsPrimary(),
            ) {
                Text(primaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button.copy(fontWeight = FontWeight.Medium))
            }
        } else {
            Button(
                onClick = onPrimaryClick,
                modifier = Modifier.weight(1f).height(56.dp),
                colors = ButtonDefaults.buttonColors().copy(MiuixTheme.colorScheme.secondary),
            ) {
                Text(primaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button.copy(fontWeight = FontWeight.Medium))
            }
        }
        Button(
            onClick = onSecondaryClick,
            modifier = Modifier.weight(1f).height(56.dp),
            colors = ButtonDefaults.buttonColors().copy(MiuixTheme.colorScheme.secondary),
        ) {
            Text(secondaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button.copy(fontWeight = FontWeight.Medium))
        }
    }
}

@Composable
private fun ActionGrid(actions: List<GridActionItem>) {
    actions.chunked(2).forEach { rowActions ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            rowActions.forEach { item ->

                val currentBgColor = if (item.isError) MiuixTheme.colorScheme.error else MiuixTheme.colorScheme.secondary

                Button(
                    onClick = item.action,
                    modifier = Modifier.weight(1f).height(56.dp),
                    colors = ButtonDefaults.buttonColors().copy(currentBgColor),
                    insideMargin = PaddingValues(horizontal = 12.dp, vertical = 14.dp),
                ) {
                    Text(
                        text = item.label,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = TextAlign.Center,
                        color = if (item.isError) MiuixTheme.colorScheme.onError else androidx.compose.ui.graphics.Color.Unspecified,
                        style = MiuixTheme.textStyles.button.copy(fontWeight = FontWeight.Medium),
                    )
                }
            }
            if (rowActions.size == 1) {
                Spacer(modifier = Modifier.weight(1f))
            }
        }
        Spacer(Modifier.height(10.dp))
    }
}

@Composable
private fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.surfaceContainerHigh.copy(0.45f),
            contentColor = MiuixTheme.colorScheme.onSurfaceContainerHigh,
        ),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            content = content,
        )
    }
}

@Composable
private fun StatusChip(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    supportingText: String? = null,
    metaText: String? = null,
    emphasized: Boolean = false,
    onClick: (() -> Unit)? = null,
) {
    val containerColor = if (emphasized) {
        MiuixTheme.colorScheme.primaryVariant
    } else {
        MiuixTheme.colorScheme.surfaceContainerHighest
    }
    val contentColor = if (emphasized) {
        MiuixTheme.colorScheme.onPrimaryVariant
    } else {
        MiuixTheme.colorScheme.onSurfaceContainerHighest
    }
    Card(
        modifier = modifier.heightIn(min = 118.dp),
        colors = CardDefaults.defaultColors(color = containerColor, contentColor = contentColor),
        onClick = onClick,
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label.uppercase(Locale.US),
                style = MiuixTheme.textStyles.footnote2,
                color = if (emphasized) {
                    MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.72f)
                } else {
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.title3.copy(fontWeight = FontWeight.Medium),
                color = if (emphasized) Color.White else MiuixTheme.colorScheme.onSurfaceContainerHighest,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (supportingText != null) {
                Text(
                    text = supportingText,
                    style = MiuixTheme.textStyles.footnote1,
                    color = if (emphasized) {
                        MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.84f)
                    } else {
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    },
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (metaText != null) {
                Text(
                    text = metaText,
                    style = MiuixTheme.textStyles.footnote1,
                    color = if (emphasized) {
                        MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.84f)
                    } else {
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun MetricCard(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    valueMaxLines: Int = 2,
    monospace: Boolean = false,
) {
    Card(
        modifier = modifier.heightIn(min = 96.dp),
        colors = CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.surfaceContainerHighest,
            contentColor = MiuixTheme.colorScheme.onSurfaceContainerHighest,
        ),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label.uppercase(Locale.US),
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.main,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                maxLines = valueMaxLines,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun hookSummaryValue(isHooked: Boolean, hookCheckCompleted: Boolean): String = when {
    isHooked -> stringResource(R.string.state_hooked_short)
    hookCheckCompleted -> stringResource(R.string.state_not_hooked_short)
    else -> stringResource(R.string.state_checking_short)
}

@Composable
private fun hookSummarySupportingText(
    isHooked: Boolean,
    hookCheckCompleted: Boolean,
    hookedPackage: String?,
): String = if (isHooked && hookedPackage != null) {
    hookedPackage
} else {
    stringResource(R.string.status_tap_recheck)
}

@Composable
private fun hookSummaryMetaText(isHooked: Boolean, hookedPid: Int): String = if (isHooked && hookedPid > 0) {
    stringResource(R.string.status_pid, hookedPid)
} else {
    ""
}

@Composable
private fun InfoPanel(
    title: String,
    text: String,
    monospace: Boolean = false,
    emphasized: Boolean = false,
) {
    val containerColor = if (emphasized) {
        MiuixTheme.colorScheme.errorContainer
    } else {
        MiuixTheme.colorScheme.surfaceContainerHighest
    }
    val contentColor = if (emphasized) {
        MiuixTheme.colorScheme.onErrorContainer
    } else {
        MiuixTheme.colorScheme.onSurfaceContainerHighest
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = containerColor, contentColor = contentColor),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (title.isNotEmpty()) {
                Text(title, style = MiuixTheme.textStyles.footnote2, color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.45f))
            }
            SelectionContainer {
                Text(
                    text = text,
                    modifier = Modifier
                        .fillMaxWidth()
                        .wrapContentHeight(),
                    fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                    style = MiuixTheme.textStyles.body1,
                )
            }
        }
    }
}

@Composable
private fun MonospaceBlock(text: String, modifier: Modifier = Modifier) {
    SelectionContainer {
        Text(
            text = text,
            modifier = modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            fontFamily = FontFamily.Monospace,
            style = MiuixTheme.textStyles.body1,
        )
    }
}

// For Android Studio preview compose interface.
@Preview(showBackground = true, device = "id:pixel_9_pro")
@Composable
private fun PreviewFuseHideHomeScreen() {
    io.github.xiaotong6666.fusehide.ui.theme.fuseHideTheme {
        FuseHideHomeScreen(
            selectedTab = 0, // 0 预览配置页，改成 1 预览测试页
            onTabSelected = {},
            infoText = "Kernel: 6.1.118\nDevice: Fuxi\nSDK: 3600000",
            statusText = "Hooked: com.example.app (1234)",
            isHooked = true,
            hookedPackage = "com.example.app",
            hookedPid = 1234,
            hookCheckCompleted = true,
            configStatusText = "The saved hidden configuration has been loaded.",
            lastAckTokenText = "-",
            lastAckResultText = "-",
            lastApplyTimeText = "-",
            draftVsAppliedDiff = HideConfigDiff(
                hasDifferences = false,
                summary = "None",
                details = "",
            ),
            appliedConfigSnapshotText = "Current native config snapshot...",
            highlightConfigResults = false,
            configResultsScrollToken = 0,
            enableHideAllRootEntries = true,
            hideAllRootEntriesExemptionsText = "Android\nDCIM\nDocument\nDownload\nMovies\nPictures",
            hiddenTargetsText = "xinhao\nMT2",
            hiddenPackagesText = "com.eltavine.duckdetector\nio.github.xiaotong6666.fusehide\nio.github.a13e300.fusefixer",
            pathText = "/storage/emulated/0/Android",
            pathText2 = "",
            outputText = "Stat /storage/emulated/0/Android -> OK",

            onStatusClick = {},
            onEnableHideAllRootEntriesChanged = {},
            onHideAllRootEntriesExemptionsChanged = {},
            onHiddenTargetsChanged = {},
            onHiddenPackagesChanged = {},
            onSaveConfigClick = {},
            onApplyConfigClick = {},
            onResetConfigClick = {},
            onRefreshAppliedConfigClick = {},
            onPathChanged = {},
            onPath2Changed = {},
            onStatClick = {},
            onAccessClick = {},
            onListClick = {},
            onOpenClick = {},
            onGetConClick = {},
            onCreateClick = {},
            onMkdirClick = {},
            onMoveClick = {},
            onRmdirClick = {},
            onUnlinkClick = {},
            onAllPkgClick = {},
            onInsertZwjClick = {},
            onClearClick = {},
            onResetClick = {},
            onCopyAllClick = {},
            onSelfDataClick = {},
        )
    }
}
