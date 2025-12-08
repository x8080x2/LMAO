// Enhanced Sidebar Menu with State Persistence
$.sidebarMenu = function (menu) {
	var animationSpeed = 300;

	// Function to save menu state to localStorage
	function saveMenuState(menuId, isOpen, isActive) {
		var menuStates = JSON.parse(localStorage.getItem('sidebarMenuStates')) || {};
		menuStates[menuId] = {
			isOpen: isOpen,
			isActive: isActive,
			timestamp: Date.now()
		};
		localStorage.setItem('sidebarMenuStates', JSON.stringify(menuStates));
	}

	// Function to get current page from URL
	function getCurrentPage() {
		var path = window.location.pathname;
		var page = path.split('/').pop() || 'index';
		// Remove .php extension if present
		page = page.replace('.php', '');
		return page;
	}

	// Function to set active menu item based on current page
	function setActiveMenuItem() {
		var currentPage = getCurrentPage();
		var $sidebarMenu = $(menu);
		
		// Remove all active classes first
		$sidebarMenu.find('li').removeClass('active');
		$sidebarMenu.find('li a').removeClass('active');
		
		// Find and activate current page menu item
		$sidebarMenu.find('a[href="' + currentPage + '"], a[href="' + currentPage + '.php"]').each(function() {
			var $link = $(this);
			var $parentLi = $link.closest('li');
			
			// Add active class to the menu item
			$parentLi.addClass('active');
			$link.addClass('active');
			
			// If it's a submenu item, also activate and open parent
			if ($parentLi.closest('ul').hasClass('treeview-menu')) {
				var $parentTreeview = $parentLi.closest('ul').parent('li');
				$parentTreeview.addClass('active');
				$parentTreeview.find('> a').addClass('active');
				$parentLi.closest('ul').show().addClass('menu-open');
				
				// Save state for parent menu
				var parentMenuId = $parentTreeview.find('> a').attr('href') || $parentTreeview.index();
				saveMenuState(parentMenuId, true, true);
			}
			
			// Save state for current menu item
			var menuId = $link.attr('href') || $parentLi.index();
			saveMenuState(menuId, false, true);
		});
	}

	// Function to restore menu states from localStorage
	function restoreMenuStates() {
		var menuStates = JSON.parse(localStorage.getItem('sidebarMenuStates')) || {};
		var $sidebarMenu = $(menu);
		
		// Restore treeview menu states
		$sidebarMenu.find('.treeview').each(function() {
			var $treeview = $(this);
			var $link = $treeview.find('> a');
			var menuId = $link.attr('href') || $treeview.index();
			
			if (menuStates[menuId] && menuStates[menuId].isOpen) {
				$treeview.find('.treeview-menu').show().addClass('menu-open');
				$treeview.addClass('active');
			}
		});
	}

	$(menu).on("click", "li a", function (e) {
		var $this = $(this);
		var $parentLi = $this.parent('li');
		var checkElement = $this.next();
		var menuId = $this.attr('href') || $parentLi.index();

		// Handle treeview menus
		if (checkElement.is(".treeview-menu")) {
			e.preventDefault();
			
			if (checkElement.is(":visible")) {
				// Close menu
				checkElement.slideUp(animationSpeed, function () {
					checkElement.removeClass("menu-open");
				});
				$parentLi.removeClass("active");
				$this.removeClass("active");
				saveMenuState(menuId, false, false);
			} else {
				// Open menu
				var parent = $this.parents("ul").first();
				var ul = parent.find("ul:visible").slideUp(animationSpeed);
				ul.removeClass("menu-open");
				
				// Remove active from other treeview items
				parent.find("li.treeview").removeClass("active");
				parent.find("li.treeview > a").removeClass("active");
				
				checkElement.slideDown(animationSpeed, function () {
					checkElement.addClass("menu-open");
				});
				$parentLi.addClass("active");
				$this.addClass("active");
				saveMenuState(menuId, true, true);
			}
		} else {
			// Handle regular menu items (navigation)
			var parent = $this.parents("ul").first();
			
			// Remove active from all menu items
			parent.find("li").removeClass("active");
			parent.find("li a").removeClass("active");
			
			// Add active to clicked item
			$parentLi.addClass("active");
			$this.addClass("active");
			
			// Save state
			saveMenuState(menuId, false, true);
			
			// If it's a submenu item, keep parent active
			if (parent.hasClass('treeview-menu')) {
				var $parentTreeview = parent.parent('li');
				$parentTreeview.addClass('active');
				$parentTreeview.find('> a').addClass('active');
			}
		}
	});

	// Function to clear all menu states (utility function)
	window.clearSidebarMenuStates = function() {
		localStorage.removeItem('sidebarMenuStates');
		location.reload();
	};

	// Initialize menu states on page load
	$(document).ready(function() {
		restoreMenuStates();
		setActiveMenuItem();
	});

	// Update active state when navigating back/forward
	$(window).on('popstate', function() {
		setTimeout(function() {
			setActiveMenuItem();
		}, 100);
	});
};
$.sidebarMenu($(".sidebar-menu"));

// Custom Sidebar JS
jQuery(function ($) {
	// Unified toggle sidebar functionality for both desktop and mobile
	$(".toggle-sidebar").on("click", function (e) {
		e.preventDefault();
		e.stopPropagation();
		
		// Add active class to button for animation
		$(this).toggleClass('active');
		
		// Use the built-in Bootstrap functionality
		$(".page-wrapper").toggleClass("toggled");
		
		// Add overlay for mobile if needed
		if ($(window).width() <= 991) {
			if ($(".page-wrapper").hasClass("toggled")) {
				// Create overlay when sidebar opens on mobile
				if (!$('.mobile-sidebar-overlay').length) {
					$('body').append('<div class="mobile-sidebar-overlay active"></div>');
				}
				$('body').addClass('sidebar-open');
			} else {
				// Remove overlay when sidebar closes
				$('.mobile-sidebar-overlay').remove();
				$('body').removeClass('sidebar-open');
			}
		}
	});

	// Toggle sidebar overlay (legacy support)
	$("#overlay").on("click", function () {
		$(".page-wrapper").toggleClass("toggled");
		$(".toggle-sidebar").removeClass('active');
	});

	// Handle mobile overlay click to close sidebar
	$(document).on('click', '.mobile-sidebar-overlay', function() {
		$(".page-wrapper").removeClass("toggled");
		$(".toggle-sidebar").removeClass('active');
		$(this).remove();
		$('body').removeClass('sidebar-open');
	});

	// Handle window resize - unified logic
	$(window).on('resize', function() {
		if ($(window).width() > 991) {
			// Desktop: clean up mobile overlay and reset button
			$('.mobile-sidebar-overlay').remove();
			$('body').removeClass('sidebar-open');
			$('.toggle-sidebar').removeClass('active');
		} else {
			// Mobile: close sidebar when resizing to mobile
			if ($(window).width() <= 768) {
				$(".page-wrapper").removeClass("toggled");
				$('.toggle-sidebar').removeClass('active');
				$('.mobile-sidebar-overlay').remove();
				$('body').removeClass('sidebar-open');
			}
		}
	});
});

/***********
***********
***********
	Bootstrap JS 
***********
***********
***********/

// Tooltip
var tooltipTriggerList = [].slice.call(
	document.querySelectorAll('[data-bs-toggle="tooltip"]')
);
var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
	return new bootstrap.Tooltip(tooltipTriggerEl);
});

// Popover
var popoverTriggerList = [].slice.call(
	document.querySelectorAll('[data-bs-toggle="popover"]')
);
var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
	return new bootstrap.Popover(popoverTriggerEl);
});

// Card Loading
$(function () {
	$(".card-loader").fadeOut(2000);
});
