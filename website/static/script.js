document.addEventListener("DOMContentLoaded", (event) => {
    const menuItems = document.querySelectorAll(".menu-item")
    const contentSections = document.querySelectorAll(".content-section")
  
    menuItems.forEach((item) => {
      item.addEventListener("click", (e) => {
        e.preventDefault()
        const targetId = item.getAttribute("data-target")
  
        // Hide all content sections
        contentSections.forEach((section) => {
          section.classList.remove("active")
        })
  
        // Show the target content section
        const targetSection = document.getElementById(targetId)
        if (targetSection) {
          targetSection.classList.add("active")
        }
  
        // Update active state of menu items
        menuItems.forEach((menuItem) => {
          menuItem.classList.remove("active")
        })
        item.classList.add("active")
      })
    })
  })
  
  