#[cfg(windows)]
mod windows_app {
    use std::{
        cell::RefCell,
        path::{Path, PathBuf},
        sync::OnceLock,
    };

    use anyhow::Context as _;
    use windows::{
        core::{w, PCWSTR},
        Win32::{
            Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM},
            System::LibraryLoader::GetModuleHandleW,
            UI::WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DispatchMessageW, GetClientRect, GetMessageW,
                GetWindowTextLengthW, GetWindowTextW, LoadCursorW, MessageBoxW, MoveWindow,
                PostQuitMessage, RegisterClassW, SetWindowTextW, ShowWindow, TranslateMessage,
                ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_LEFT, ES_MULTILINE, ES_READONLY, HMENU,
                IDC_ARROW, MB_ICONERROR, MB_OK, MSG, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE,
                WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD,
                WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
            },
        },
    };

    use scp2p_desktop::{
        commands, CommunityBrowseView, CommunityView, DesktopAppState, DesktopClientConfig,
        PeerView, PublicShareView, PublishResultView, PublishVisibility, RuntimeStatus,
        SearchResultsView, StartNodeRequest, SubscriptionView,
    };

    const ID_DB_PATH: isize = 1001;
    const ID_BIND_QUIC: isize = 1002;
    const ID_BIND_TCP: isize = 1003;
    const ID_BOOTSTRAP: isize = 1004;
    const ID_STATUS: isize = 1005;
    const ID_SUBSCRIPTION: isize = 1006;
    const ID_PUBLIC_INDEX: isize = 1007;
    const ID_COMMUNITY_ID: isize = 1008;
    const ID_COMMUNITY_PUBKEY: isize = 1009;
    const ID_SEARCH: isize = 1010;
    const ID_DATA: isize = 1011;
    const ID_DOWNLOAD_CONTENT: isize = 1012;
    const ID_DOWNLOAD_PATH: isize = 1013;
    const ID_PUBLISH_TITLE: isize = 1014;
    const ID_PUBLISH_NAME: isize = 1015;
    const ID_PUBLISH_TEXT: isize = 1016;
    const ID_PUBLISH_VISIBILITY: isize = 1017;
    const ID_PUBLISH_COMMUNITIES: isize = 1018;

    const ID_START: isize = 1101;
    const ID_STOP: isize = 1102;
    const ID_LOAD: isize = 1103;
    const ID_SAVE: isize = 1104;
    const ID_REFRESH: isize = 1105;
    const ID_SUBSCRIBE: isize = 1106;
    const ID_UNSUBSCRIBE: isize = 1107;
    const ID_SYNC: isize = 1108;
    const ID_SEARCH_BTN: isize = 1109;
    const ID_DOWNLOAD_BTN: isize = 1110;
    const ID_PUBLISH_BTN: isize = 1111;
    const ID_BROWSE_PUBLIC: isize = 1112;
    const ID_SUBSCRIBE_PUBLIC: isize = 1113;
    const ID_JOIN_COMMUNITY: isize = 1114;
    const ID_BROWSE_COMMUNITY: isize = 1115;

    const WINDOW_CLASS: &str = "SCP2PDesktopWindow";
    const CONFIG_FILE: &str = "scp2p-desktop-config.cbor";

    #[derive(Copy, Clone)]
    struct UiHandles {
        db_path: HWND,
        bind_quic: HWND,
        bind_tcp: HWND,
        bootstrap: HWND,
        subscription: HWND,
        public_index: HWND,
        community_id: HWND,
        community_pubkey: HWND,
        search: HWND,
        download_content: HWND,
        download_path: HWND,
        publish_title: HWND,
        publish_name: HWND,
        publish_text: HWND,
        publish_visibility: HWND,
        publish_communities: HWND,
        status: HWND,
        data: HWND,
    }

    #[derive(Copy, Clone)]
    struct Bounds {
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    }

    struct AppContext {
        runtime: tokio::runtime::Runtime,
        app_state: DesktopAppState,
        config_path: PathBuf,
    }

    static APP: OnceLock<AppContext> = OnceLock::new();

    thread_local! {
        static UI: RefCell<Option<UiHandles>> = const { RefCell::new(None) };
    }

    pub fn run() -> anyhow::Result<()> {
        let module = unsafe { GetModuleHandleW(None) }?;
        let hinstance: HINSTANCE = module.into();
        let _ = APP.set(AppContext {
            runtime: tokio::runtime::Runtime::new().context("create tokio runtime")?,
            app_state: DesktopAppState::new(),
            config_path: std::env::current_dir()
                .context("resolve current dir")?
                .join(CONFIG_FILE),
        });

        let class_name = wide(WINDOW_CLASS);
        let window_class = WNDCLASSW {
            hCursor: unsafe { LoadCursorW(None, IDC_ARROW)? },
            hInstance: hinstance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            lpfnWndProc: Some(window_proc),
            ..Default::default()
        };

        unsafe {
            RegisterClassW(&window_class);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                w!("SCP2P Desktop Client"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                100,
                100,
                1100,
                980,
                None,
                None,
                Some(hinstance),
                None,
            )?;
            let _ = ShowWindow(hwnd, SW_SHOW);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        Ok(())
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_CREATE => match create_controls(hwnd) {
                Ok(()) => LRESULT(0),
                Err(err) => {
                    show_error(hwnd, &format!("{err:#}"));
                    LRESULT(0)
                }
            },
            WM_SIZE => {
                layout_controls(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => match handle_command(hwnd, wparam) {
                Ok(()) => LRESULT(0),
                Err(err) => {
                    show_error(hwnd, &format!("{err:#}"));
                    LRESULT(0)
                }
            },
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    fn create_controls(hwnd: HWND) -> anyhow::Result<()> {
        let instance: HINSTANCE = unsafe { GetModuleHandleW(None)?.into() };
        let label_style = WS_CHILD | WS_VISIBLE;
        let edit_style = WINDOW_STYLE(
            (WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP).0
                | ES_LEFT as u32
                | ES_AUTOHSCROLL as u32,
        );
        let multi_style = WINDOW_STYLE(
            (WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_TABSTOP).0
                | ES_LEFT as u32
                | ES_MULTILINE as u32
                | ES_AUTOVSCROLL as u32,
        );
        let readonly_multi_style = WINDOW_STYLE(multi_style.0 | ES_READONLY as u32);

        unsafe {
            make_label(hwnd, instance, "State DB", b(10, 12, 120, 20), label_style)?;
            let db_path = make_edit(hwnd, instance, ID_DB_PATH, b(140, 10, 920, 24), edit_style)?;

            make_label(hwnd, instance, "Bind QUIC", b(10, 46, 120, 20), label_style)?;
            let bind_quic = make_edit(
                hwnd,
                instance,
                ID_BIND_QUIC,
                b(140, 44, 240, 24),
                edit_style,
            )?;

            make_label(hwnd, instance, "Bind TCP", b(400, 46, 100, 20), label_style)?;
            let bind_tcp = make_edit(hwnd, instance, ID_BIND_TCP, b(500, 44, 240, 24), edit_style)?;

            make_label(
                hwnd,
                instance,
                "Bootstrap Peers",
                b(10, 80, 120, 20),
                label_style,
            )?;
            let bootstrap = make_edit(
                hwnd,
                instance,
                ID_BOOTSTRAP,
                b(140, 78, 920, 100),
                multi_style,
            )?;

            let _ = make_button(hwnd, instance, ID_LOAD, "Load Config", b(140, 190, 110, 30))?;
            let _ = make_button(hwnd, instance, ID_SAVE, "Save Config", b(260, 190, 110, 30))?;
            let _ = make_button(hwnd, instance, ID_START, "Start Node", b(380, 190, 110, 30))?;
            let _ = make_button(hwnd, instance, ID_STOP, "Stop Node", b(500, 190, 110, 30))?;
            let _ = make_button(hwnd, instance, ID_REFRESH, "Refresh", b(620, 190, 110, 30))?;
            let _ = make_button(
                hwnd,
                instance,
                ID_SUBSCRIBE,
                "Subscribe",
                b(740, 190, 110, 30),
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_UNSUBSCRIBE,
                "Unsubscribe",
                b(860, 190, 110, 30),
            )?;
            let _ = make_button(hwnd, instance, ID_SYNC, "Sync Now", b(980, 190, 80, 30))?;

            make_label(hwnd, instance, "Share ID", b(10, 230, 120, 20), label_style)?;
            let subscription = make_edit(
                hwnd,
                instance,
                ID_SUBSCRIPTION,
                b(140, 228, 920, 24),
                edit_style,
            )?;

            make_label(hwnd, instance, "Public #", b(10, 264, 120, 20), label_style)?;
            let public_index = make_edit(
                hwnd,
                instance,
                ID_PUBLIC_INDEX,
                b(140, 262, 100, 24),
                edit_style,
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_BROWSE_PUBLIC,
                "Browse Public",
                b(250, 260, 120, 30),
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_SUBSCRIBE_PUBLIC,
                "Subscribe Public",
                b(380, 260, 130, 30),
            )?;

            make_label(
                hwnd,
                instance,
                "Community ID",
                b(10, 298, 120, 20),
                label_style,
            )?;
            let community_id = make_edit(
                hwnd,
                instance,
                ID_COMMUNITY_ID,
                b(140, 296, 920, 24),
                edit_style,
            )?;
            make_label(
                hwnd,
                instance,
                "Community Pubkey",
                b(10, 332, 120, 20),
                label_style,
            )?;
            let community_pubkey = make_edit(
                hwnd,
                instance,
                ID_COMMUNITY_PUBKEY,
                b(140, 330, 700, 24),
                edit_style,
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_JOIN_COMMUNITY,
                "Join Community",
                b(850, 328, 100, 30),
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_BROWSE_COMMUNITY,
                "Browse Community",
                b(960, 328, 100, 30),
            )?;

            make_label(hwnd, instance, "Search", b(10, 366, 120, 20), label_style)?;
            let search = make_edit(hwnd, instance, ID_SEARCH, b(140, 364, 800, 24), edit_style)?;
            let _ = make_button(
                hwnd,
                instance,
                ID_SEARCH_BTN,
                "Search",
                b(950, 362, 110, 30),
            )?;

            make_label(
                hwnd,
                instance,
                "Download Content",
                b(10, 400, 120, 20),
                label_style,
            )?;
            let download_content = make_edit(
                hwnd,
                instance,
                ID_DOWNLOAD_CONTENT,
                b(140, 398, 800, 24),
                edit_style,
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_DOWNLOAD_BTN,
                "Download",
                b(950, 396, 110, 30),
            )?;

            make_label(
                hwnd,
                instance,
                "Output Path",
                b(10, 434, 120, 20),
                label_style,
            )?;
            let download_path = make_edit(
                hwnd,
                instance,
                ID_DOWNLOAD_PATH,
                b(140, 432, 920, 24),
                edit_style,
            )?;

            make_label(
                hwnd,
                instance,
                "Publish Title",
                b(10, 468, 120, 20),
                label_style,
            )?;
            let publish_title = make_edit(
                hwnd,
                instance,
                ID_PUBLISH_TITLE,
                b(140, 466, 600, 24),
                edit_style,
            )?;
            make_label(
                hwnd,
                instance,
                "Visibility",
                b(760, 468, 80, 20),
                label_style,
            )?;
            let publish_visibility = make_edit(
                hwnd,
                instance,
                ID_PUBLISH_VISIBILITY,
                b(850, 466, 210, 24),
                edit_style,
            )?;
            make_label(
                hwnd,
                instance,
                "Publish Communities",
                b(10, 502, 120, 20),
                label_style,
            )?;
            let publish_communities = make_edit(
                hwnd,
                instance,
                ID_PUBLISH_COMMUNITIES,
                b(140, 500, 920, 24),
                edit_style,
            )?;

            make_label(
                hwnd,
                instance,
                "Item Name",
                b(10, 536, 120, 20),
                label_style,
            )?;
            let publish_name = make_edit(
                hwnd,
                instance,
                ID_PUBLISH_NAME,
                b(140, 534, 800, 24),
                edit_style,
            )?;
            let _ = make_button(
                hwnd,
                instance,
                ID_PUBLISH_BTN,
                "Publish",
                b(950, 532, 110, 30),
            )?;

            make_label(
                hwnd,
                instance,
                "Publish Text",
                b(10, 570, 120, 20),
                label_style,
            )?;
            let publish_text = make_edit(
                hwnd,
                instance,
                ID_PUBLISH_TEXT,
                b(140, 568, 920, 80),
                multi_style,
            )?;

            make_label(
                hwnd,
                instance,
                "Runtime Status",
                b(10, 658, 140, 20),
                label_style,
            )?;
            let status = make_edit(
                hwnd,
                instance,
                ID_STATUS,
                b(10, 684, 1050, 120),
                readonly_multi_style,
            )?;

            make_label(
                hwnd,
                instance,
                "Peers / Subs / Communities / Public / Search / Publish",
                b(10, 814, 360, 20),
                label_style,
            )?;
            let data = make_edit(
                hwnd,
                instance,
                ID_DATA,
                b(10, 840, 1050, 84),
                readonly_multi_style,
            )?;

            UI.with(|ui| {
                *ui.borrow_mut() = Some(UiHandles {
                    db_path,
                    bind_quic,
                    bind_tcp,
                    bootstrap,
                    subscription,
                    public_index,
                    community_id,
                    community_pubkey,
                    search,
                    download_content,
                    download_path,
                    publish_title,
                    publish_name,
                    publish_text,
                    publish_visibility,
                    publish_communities,
                    status,
                    data,
                });
            });
        }

        set_text(ui_handles()?.publish_visibility, "private")?;
        load_config_into_ui(hwnd)?;
        refresh_status(hwnd)?;
        Ok(())
    }

    fn handle_command(hwnd: HWND, wparam: WPARAM) -> anyhow::Result<()> {
        match (wparam.0 & 0xffff) as isize {
            ID_LOAD => load_config_into_ui(hwnd),
            ID_SAVE => save_config_from_ui(hwnd),
            ID_START => start_node_from_ui(),
            ID_STOP => stop_node(),
            ID_REFRESH => refresh_status(hwnd),
            ID_SUBSCRIBE => subscribe_share(),
            ID_UNSUBSCRIBE => unsubscribe_share(),
            ID_SYNC => sync_now(),
            ID_BROWSE_PUBLIC => browse_public_shares(),
            ID_SUBSCRIBE_PUBLIC => subscribe_public_share(),
            ID_JOIN_COMMUNITY => join_community(),
            ID_BROWSE_COMMUNITY => browse_community(),
            ID_SEARCH_BTN => search_catalogs(),
            ID_DOWNLOAD_BTN => download_content(),
            ID_PUBLISH_BTN => publish_text_share(),
            _ => Ok(()),
        }
    }

    fn load_config_into_ui(hwnd: HWND) -> anyhow::Result<()> {
        let app = app()?;
        let config = app.runtime.block_on(commands::load_client_config(
            &app.app_state,
            app.config_path.to_string_lossy().to_string(),
        ))?;
        set_ui_from_config(&config)?;
        refresh_status(hwnd)
    }

    fn save_config_from_ui(hwnd: HWND) -> anyhow::Result<()> {
        let app = app()?;
        let config = read_config_from_ui()?;
        app.runtime.block_on(commands::save_client_config(
            &app.app_state,
            app.config_path.to_string_lossy().to_string(),
            config,
        ))?;
        refresh_status(hwnd)
    }

    fn start_node_from_ui() -> anyhow::Result<()> {
        let app = app()?;
        let config = read_config_from_ui()?;
        let request = StartNodeRequest {
            state_db_path: config.state_db_path,
            bind_quic: config.bind_quic,
            bind_tcp: config.bind_tcp,
            bootstrap_peers: config.bootstrap_peers,
        };
        let status = app
            .runtime
            .block_on(commands::start_node(&app.app_state, request))?;
        set_status_text(&format_status(&app.config_path, &status))?;
        refresh_snapshot()
    }

    fn stop_node() -> anyhow::Result<()> {
        let app = app()?;
        let status = app.runtime.block_on(commands::stop_node(&app.app_state))?;
        set_status_text(&format_status(&app.config_path, &status))?;
        set_data_text("Node stopped.\r\n")
    }

    fn refresh_status(_hwnd: HWND) -> anyhow::Result<()> {
        let app = app()?;
        let status = app
            .runtime
            .block_on(commands::runtime_status(&app.app_state))?;
        set_status_text(&format_status(&app.config_path, &status))?;
        refresh_snapshot()
    }

    fn subscribe_share() -> anyhow::Result<()> {
        let app = app()?;
        let share_id = get_text(ui_handles()?.subscription)?;
        let subs = app
            .runtime
            .block_on(commands::subscribe_share(&app.app_state, share_id))?;
        set_data_text(&format_subscriptions_only(&subs))
    }

    fn unsubscribe_share() -> anyhow::Result<()> {
        let app = app()?;
        let share_id = get_text(ui_handles()?.subscription)?;
        let subs = app
            .runtime
            .block_on(commands::unsubscribe_share(&app.app_state, share_id))?;
        set_data_text(&format_subscriptions_only(&subs))
    }

    fn sync_now() -> anyhow::Result<()> {
        let app = app()?;
        let subs = app.runtime.block_on(commands::sync_now(&app.app_state))?;
        set_data_text(&format_subscriptions_only(&subs))
    }

    fn browse_public_shares() -> anyhow::Result<()> {
        let app = app()?;
        let shares = app
            .runtime
            .block_on(commands::browse_public_shares(&app.app_state))?;
        set_data_text(&format_public_shares(&shares))
    }

    fn subscribe_public_share() -> anyhow::Result<()> {
        let app = app()?;
        let index_text = get_text(ui_handles()?.public_index)?;
        let index = index_text.trim().parse::<usize>()?;
        let subs = app
            .runtime
            .block_on(commands::subscribe_public_share(&app.app_state, index))?;
        set_data_text(&format_subscriptions_only(&subs))
    }

    fn join_community() -> anyhow::Result<()> {
        let app = app()?;
        let ui = ui_handles()?;
        let share_id = get_text(ui.community_id)?;
        let share_pubkey = get_text(ui.community_pubkey)?;
        let communities = app.runtime.block_on(commands::join_community(
            &app.app_state,
            share_id,
            share_pubkey,
        ))?;
        set_data_text(&format_communities(&communities))
    }

    fn browse_community() -> anyhow::Result<()> {
        let app = app()?;
        let share_id = get_text(ui_handles()?.community_id)?;
        let browse = app
            .runtime
            .block_on(commands::browse_community(&app.app_state, share_id))?;
        set_data_text(&format_community_browse(&browse))
    }

    fn search_catalogs() -> anyhow::Result<()> {
        let app = app()?;
        let query = get_text(ui_handles()?.search)?;
        let results = app
            .runtime
            .block_on(commands::search_catalogs(&app.app_state, query))?;
        set_data_text(&format_search_results(&results))
    }

    fn download_content() -> anyhow::Result<()> {
        let app = app()?;
        let ui = ui_handles()?;
        let content_id = get_text(ui.download_content)?;
        let output_path = get_text(ui.download_path)?;
        app.runtime.block_on(commands::download_content(
            &app.app_state,
            content_id.clone(),
            output_path.clone(),
        ))?;
        set_data_text(&format!(
            "Download complete.\r\ncontent_id={}\r\nout={}\r\n",
            content_id, output_path
        ))
    }

    fn publish_text_share() -> anyhow::Result<()> {
        let app = app()?;
        let ui = ui_handles()?;
        let title = get_text(ui.publish_title)?;
        let item_name = get_text(ui.publish_name)?;
        let item_text = get_text(ui.publish_text)?;
        let visibility = parse_publish_visibility(&get_text(ui.publish_visibility)?)?;
        let communities = parse_line_tokens(&get_text(ui.publish_communities)?);
        let result = app.runtime.block_on(commands::publish_text_share(
            &app.app_state,
            title,
            item_name,
            item_text,
            visibility,
            communities,
        ))?;
        set_data_text(&format_publish_result(&result))
    }

    fn refresh_snapshot() -> anyhow::Result<()> {
        let app = app()?;
        let peers = match app.runtime.block_on(commands::list_peers(&app.app_state)) {
            Ok(peers) => peers,
            Err(_) => {
                set_data_text(
                    "Start the node to inspect peers, subscriptions, search, and publish.\r\n",
                )?;
                return Ok(());
            }
        };
        let subs = app
            .runtime
            .block_on(commands::list_subscriptions(&app.app_state))?;
        let communities = app
            .runtime
            .block_on(commands::list_communities(&app.app_state))?;
        set_data_text(&format_snapshot(&peers, &subs, &communities))
    }

    fn app() -> anyhow::Result<&'static AppContext> {
        APP.get().context("application context not initialized")
    }

    fn read_config_from_ui() -> anyhow::Result<DesktopClientConfig> {
        let ui = ui_handles()?;
        Ok(DesktopClientConfig {
            state_db_path: get_text(ui.db_path)?,
            bind_quic: parse_optional_socket(&get_text(ui.bind_quic)?)?,
            bind_tcp: parse_optional_socket(&get_text(ui.bind_tcp)?)?,
            bootstrap_peers: parse_bootstrap_lines(&get_text(ui.bootstrap)?),
        })
    }

    fn set_ui_from_config(config: &DesktopClientConfig) -> anyhow::Result<()> {
        let ui = ui_handles()?;
        set_text(ui.db_path, &config.state_db_path)?;
        set_text(ui.bind_quic, &socket_text(config.bind_quic))?;
        set_text(ui.bind_tcp, &socket_text(config.bind_tcp))?;
        set_text(ui.bootstrap, &config.bootstrap_peers.join("\r\n"))?;
        Ok(())
    }

    fn ui_handles() -> anyhow::Result<UiHandles> {
        UI.with(|ui| {
            ui.borrow()
                .as_ref()
                .copied()
                .context("UI controls not initialized")
        })
    }

    fn set_status_text(text: &str) -> anyhow::Result<()> {
        set_text(ui_handles()?.status, text)
    }

    fn set_data_text(text: &str) -> anyhow::Result<()> {
        set_text(ui_handles()?.data, text)
    }

    fn format_status(config_path: &Path, status: &RuntimeStatus) -> String {
        let mut lines = vec![
            format!("Config file: {}", config_path.display()),
            format!("Running: {}", status.running),
            format!(
                "State DB: {}",
                status
                    .state_db_path
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string())
            ),
            format!("Bind QUIC: {}", socket_text(status.bind_quic)),
            format!("Bind TCP: {}", socket_text(status.bind_tcp)),
            "Bootstrap peers:".to_string(),
        ];
        if status.bootstrap_peers.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(
                status
                    .bootstrap_peers
                    .iter()
                    .map(|peer| format!("  {peer}")),
            );
        }
        if !status.warnings.is_empty() {
            lines.push("Warnings:".to_string());
            lines.extend(status.warnings.iter().map(|warning| format!("  {warning}")));
        }
        lines.join("\r\n")
    }

    fn format_snapshot(
        peers: &[PeerView],
        subscriptions: &[SubscriptionView],
        communities: &[CommunityView],
    ) -> String {
        let mut lines = vec!["Known peers:".to_string()];
        if peers.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(peers.iter().map(|peer| {
                format!(
                    "  {} [{}] last_seen={}",
                    peer.addr, peer.transport, peer.last_seen_unix
                )
            }));
        }
        lines.push("Subscriptions:".to_string());
        if subscriptions.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(subscriptions.iter().map(|sub| {
                format!(
                    "  {} seq={} trust={:?} manifest={}",
                    sub.share_id_hex,
                    sub.latest_seq,
                    sub.trust_level,
                    sub.latest_manifest_id_hex
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string())
                )
            }));
        }
        lines.push("Communities:".to_string());
        if communities.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(communities.iter().map(|community| {
                format!(
                    "  {} pubkey={}",
                    community.share_id_hex, community.share_pubkey_hex
                )
            }));
        }
        lines.join("\r\n")
    }

    fn format_subscriptions_only(subscriptions: &[SubscriptionView]) -> String {
        format_snapshot(&[], subscriptions, &[])
    }

    fn format_search_results(results: &SearchResultsView) -> String {
        let mut lines = vec![format!("Search results: {}", results.total)];
        if results.results.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(results.results.iter().map(|result| {
                format!(
                    "  score={:.2} share={} content={} name={} snippet={}",
                    result.score,
                    result.share_id_hex,
                    result.content_id_hex,
                    result.name,
                    result
                        .snippet
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string())
                )
            }));
        }
        lines.join("\r\n")
    }

    fn format_public_shares(shares: &[PublicShareView]) -> String {
        let mut lines = vec![format!("Public shares: {}", shares.len())];
        if shares.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(shares.iter().enumerate().map(|(idx, share)| {
                format!(
                    "  {}. peer={} share={} seq={} title={} desc={}",
                    idx + 1,
                    share.source_peer_addr,
                    share.share_id_hex,
                    share.latest_seq,
                    share.title.clone().unwrap_or_else(|| "<none>".to_string()),
                    share
                        .description
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string())
                )
            }));
        }
        lines.join("\r\n")
    }

    fn format_communities(communities: &[CommunityView]) -> String {
        let mut lines = vec![format!("Communities: {}", communities.len())];
        if communities.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(communities.iter().map(|community| {
                format!(
                    "  {} pubkey={}",
                    community.share_id_hex, community.share_pubkey_hex
                )
            }));
        }
        lines.join("\r\n")
    }

    fn format_community_browse(browse: &CommunityBrowseView) -> String {
        let mut lines = vec![format!("Community: {}", browse.community_share_id_hex)];
        lines.push(format!("Participants: {}", browse.participants.len()));
        if browse.participants.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(browse.participants.iter().map(|participant| {
                format!(
                    "  peer={} [{}]",
                    participant.peer_addr, participant.transport
                )
            }));
        }
        lines.push(format!(
            "Community public shares: {}",
            browse.public_shares.len()
        ));
        if browse.public_shares.is_empty() {
            lines.push("  <none>".to_string());
        } else {
            lines.extend(browse.public_shares.iter().enumerate().map(|(idx, share)| {
                format!(
                    "  {}. peer={} share={} seq={} title={} desc={}",
                    idx + 1,
                    share.source_peer_addr,
                    share.share_id_hex,
                    share.latest_seq,
                    share.title.clone().unwrap_or_else(|| "<none>".to_string()),
                    share
                        .description
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string())
                )
            }));
        }
        lines.join("\r\n")
    }

    fn format_publish_result(result: &PublishResultView) -> String {
        format!(
            "Published share.\r\nvisibility={:?}\r\ncommunities={}\r\nshare_id={}\r\nshare_pubkey={}\r\nshare_secret={}\r\nmanifest_id={}\r\nprovider={}\r\n",
            result.visibility,
            if result.community_ids_hex.is_empty() {
                "<none>".to_string()
            } else {
                result.community_ids_hex.join(", ")
            },
            result.share_id_hex,
            result.share_pubkey_hex,
            result.share_secret_hex,
            result.manifest_id_hex,
            result.provider_addr,
        )
    }

    fn parse_publish_visibility(text: &str) -> anyhow::Result<PublishVisibility> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "private" => Ok(PublishVisibility::Private),
            "public" => Ok(PublishVisibility::Public),
            other => anyhow::bail!("invalid visibility '{other}', expected private or public"),
        }
    }

    fn parse_optional_socket(text: &str) -> anyhow::Result<Option<std::net::SocketAddr>> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        Ok(Some(trimmed.parse()?))
    }

    fn parse_bootstrap_lines(text: &str) -> Vec<String> {
        parse_line_tokens(text)
    }

    fn parse_line_tokens(text: &str) -> Vec<String> {
        text.split(['\n', ',', ';'])
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.trim_end_matches('\r').to_string())
            .collect()
    }

    fn socket_text(socket: Option<std::net::SocketAddr>) -> String {
        socket.map(|value| value.to_string()).unwrap_or_default()
    }

    fn set_text(hwnd: HWND, value: &str) -> anyhow::Result<()> {
        let value = wide(value);
        unsafe { SetWindowTextW(hwnd, PCWSTR(value.as_ptr()))? };
        Ok(())
    }

    fn get_text(hwnd: HWND) -> anyhow::Result<String> {
        let len = unsafe { GetWindowTextLengthW(hwnd) };
        let mut buf = vec![0u16; len as usize + 1];
        let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
        buf.truncate(copied as usize);
        Ok(String::from_utf16(&buf)?)
    }

    fn layout_controls(hwnd: HWND) {
        let Ok(ui) = ui_handles() else {
            return;
        };
        let mut rect = RECT::default();
        unsafe {
            let _ = GetClientRect(hwnd, &mut rect);
        };
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        let margin = 10;
        let label_width = 120;
        let field_x = margin + label_width + 10;
        let field_width = width - field_x - margin;

        unsafe {
            let _ = MoveWindow(ui.db_path, field_x, 10, field_width, 24, true);
            let _ = MoveWindow(ui.bind_quic, field_x, 44, 240, 24, true);
            let _ = MoveWindow(ui.bind_tcp, field_x + 360, 44, 240, 24, true);
            let _ = MoveWindow(ui.bootstrap, field_x, 78, field_width, 100, true);
            let _ = MoveWindow(ui.subscription, field_x, 228, field_width, 24, true);
            let _ = MoveWindow(ui.public_index, field_x, 262, 100, 24, true);
            let _ = MoveWindow(ui.community_id, field_x, 296, field_width, 24, true);
            let _ = MoveWindow(
                ui.community_pubkey,
                field_x,
                330,
                field_width - 220,
                24,
                true,
            );
            let _ = MoveWindow(ui.search, field_x, 364, field_width - 120, 24, true);
            let _ = MoveWindow(
                ui.download_content,
                field_x,
                398,
                field_width - 120,
                24,
                true,
            );
            let _ = MoveWindow(ui.download_path, field_x, 432, field_width, 24, true);
            let _ = MoveWindow(ui.publish_title, field_x, 466, field_width - 320, 24, true);
            let _ = MoveWindow(
                ui.publish_visibility,
                width - margin - 210,
                466,
                210,
                24,
                true,
            );
            let _ = MoveWindow(ui.publish_communities, field_x, 500, field_width, 24, true);
            let _ = MoveWindow(ui.publish_name, field_x, 534, field_width - 120, 24, true);
            let _ = MoveWindow(ui.publish_text, field_x, 568, field_width, 80, true);
            let _ = MoveWindow(ui.status, margin, 684, width - 2 * margin, 120, true);
            let _ = MoveWindow(ui.data, margin, 840, width - 2 * margin, height - 850, true);
        }
    }

    unsafe fn make_label(
        parent: HWND,
        instance: HINSTANCE,
        text: &str,
        bounds: Bounds,
        style: WINDOW_STYLE,
    ) -> anyhow::Result<HWND> {
        let text = wide(text);
        Ok(CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            PCWSTR(text.as_ptr()),
            style,
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            Some(parent),
            None,
            Some(instance),
            None,
        )?)
    }

    unsafe fn make_edit(
        parent: HWND,
        instance: HINSTANCE,
        id: isize,
        bounds: Bounds,
        style: WINDOW_STYLE,
    ) -> anyhow::Result<HWND> {
        Ok(CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("EDIT"),
            w!(""),
            style,
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            Some(parent),
            Some(HMENU(id as _)),
            Some(instance),
            None,
        )?)
    }

    unsafe fn make_button(
        parent: HWND,
        instance: HINSTANCE,
        id: isize,
        text: &str,
        bounds: Bounds,
    ) -> anyhow::Result<HWND> {
        let text = wide(text);
        Ok(CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            PCWSTR(text.as_ptr()),
            WS_TABSTOP | WS_VISIBLE | WS_CHILD,
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            Some(parent),
            Some(HMENU(id as _)),
            Some(instance),
            None,
        )?)
    }

    const fn b(x: i32, y: i32, width: i32, height: i32) -> Bounds {
        Bounds {
            x,
            y,
            width,
            height,
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn show_error(hwnd: HWND, message: &str) {
        let message = wide(message);
        unsafe {
            let _ = MessageBoxW(
                Some(hwnd),
                PCWSTR(message.as_ptr()),
                w!("SCP2P Error"),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_app::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("scp2p-desktop currently provides a native shell only on Windows.");
}
