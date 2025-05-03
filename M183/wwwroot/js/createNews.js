function handleCancelNew(newsEntry) {
    window.location.href = "index.html";
}

function handleSaveNew() {
    var headerElement = document.getElementById("header");
    var detailElement = document.getElementById("detail");

    var data = {
        header: headerElement.innerText,
        detail: detailElement.innerText,
        authorId: getUserid(),
        isAdminNews: isAdmin()
    }
    const user = JSON.parse(localStorage.getItem(userKey)); // Get user data

    fetch("/api/News/", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${user.token}` // Add Authorization header
        },
        body: JSON.stringify(data)
    })
        .then((response) => {
            if (response.ok) {
                window.location.href = "index.html";
            }
            else {
                alert("NOK");
            }
        })
        .catch(() => {
            alert("Error");
        });
}

function createNews() {
    /* Header. */
    var mainTitle = document.createElement("h1");
    mainTitle.innerText = "New entry";

    var main = document.getElementById("main");
    // Ensure main is cleared before adding new content
    if (!main) return; // Exit if main element not found
    main.innerHTML = '';

    main.appendChild(mainTitle);

    /* New entry. */
    var divEntry = document.createElement("div");
    divEntry.classList.add("newsEntry");

    var header = document.createElement("div");
    header.id = "header";
    header.classList.add("newsHeader");
    if (isAdmin()) { // Use isAdmin() from login.js
        header.classList.add("adminNews");
    }
    header.innerText = "New header"; // Default text for new entry
    header.contentEditable = true;

    var detail = document.createElement("div");
    detail.id = "detail";
    detail.classList.add("newsDetail");
    detail.innerText = "New detail"; // Default text for new entry
    detail.contentEditable = true;

    var btnSave = document.createElement("button");
    btnSave.id = "btnSave";
    btnSave.classList.add("btnSave");
    btnSave.innerText = "Save";
    // Removed the IIFE and arg passing as it's not needed here
    btnSave.addEventListener("click", handleSaveNew);


    var btnCancel = document.createElement("button");
    btnCancel.id = "btnCancel";
    btnCancel.classList.add("btnCancel");
    btnCancel.innerText = "Cancel";
    // Removed the IIFE and arg passing as it's not needed here
    btnCancel.addEventListener("click", handleCancelNew);


    divEntry.appendChild(header);
    divEntry.appendChild(detail);
    divEntry.appendChild(btnSave);
    divEntry.appendChild(btnCancel);
    main.appendChild(divEntry);

    // Optionally focus the header field
    header.focus();
}
