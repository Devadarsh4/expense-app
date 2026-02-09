const nodemailer = require("nodemailer");


const emailClient = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.GOOGLE_EMAIL,
        pass: process.env.GOOGLE_APP_PASSWORD,
    },
});


const emailServices = {
    send: async (to, subject, body) => {
        try {
            const emailOptions = {
                from: process.env.GOOGLE_EMAIL,
                to: to,
                subject: subject,
                text: body,
            };

            const info = await emailClient.sendMail(emailOptions);
            console.log("Email sent:", info.messageId);
            return info;
        } catch (error) {
            console.error("Email send failed:", error);
            throw error;
        }
    },
};

module.exports = emailServices;