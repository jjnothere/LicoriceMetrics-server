// Luxon for timezone formatting
import { DateTime } from 'luxon';

const formatDateWithTimeZone = (date, timeZone) => {
  return DateTime.fromJSDate(date, { zone: timeZone }).toFormat('MM/dd/yyyy');
};
const isProduction = process.env.NODE_ENV === 'production';
import { MongoClient, ObjectId } from 'mongodb';
import express from 'express';
import passport from 'passport';
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';
import dotenv from 'dotenv';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import cron from 'node-cron';
import path from 'path';
import { fileURLToPath } from 'url';
import MongoStore from 'connect-mongo';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 8000;

dotenv.config(); // Load environment variables

app.use(express.json());
app.use(cookieParser());

// Configure CORS
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL_PROD 
    : process.env.FRONTEND_URL_DEV,
  credentials: true, // allows sending cookies and auth headers
}));

// Configure session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
  }),
}));

// Add logging to confirm session store is working
app.use((req, res, next) => {
  if (req.session) {
  } else {
  }
  next();
});

// Trust Heroku proxy to preserve protocol

app.set('trust proxy', 1);

// Redirect www to non-www
app.use((req, res, next) => {
  if (req.headers.host && req.headers.host.startsWith('www.')) {
    res.redirect(301, 'https://' + req.headers.host.replace(/^www\./, '') + req.url);
  } else {
    next();
  }
});

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// ─── Middleware to auto-refresh on missing accessToken ─────────────────────────
app.use(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;

  // Only try to refresh if there's no accessToken but we do have a refreshToken
  if (!req.cookies.accessToken && refreshToken) {
    try {
      const tokens = await refreshUserAccessToken(refreshToken);
      if (tokens?.newAccessToken) {
        const { newAccessToken, newRefreshToken } = tokens;

        // Reset both cookies with the correct flags
        res.cookie('accessToken', newAccessToken, {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          path: '/',
          maxAge: 2 * 60 * 60 * 1000, // 2h
        });
        res.cookie('refreshToken', newRefreshToken, {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          path: '/',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
        });

        // So any downstream code sees the fresh token
        req.cookies.accessToken = newAccessToken;
      }
    } catch (err) {
      console.error('Error refreshing tokens:', err);
    }
  }

  next();
});

// Initialize Passport for LinkedIn OAuth
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// MongoDB client setup
const url = process.env.MONGODB_URI;
const client = new MongoClient(url);

// LinkedIn Strategy for OAuth 2.0
const callbackURL = process.env.NODE_ENV === 'production'
  ? process.env.CALLBACK_URL_PROD
  : process.env.CALLBACK_URL_DEV;

// Add logs to confirm environment variables are loaded
if (!process.env.LINKEDIN_CLIENT_ID || !process.env.LINKEDIN_CLIENT_SECRET || !callbackURL) {
  console.warn('LinkedIn OAuth environment variables are missing or incomplete.');
}

// Add detailed logging to LinkedIn strategy
passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID,
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  callbackURL: callbackURL,
  scope: ['r_ads_reporting', 'r_ads', 'r_basicprofile', 'r_organization_social'],
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { profile, accessToken, refreshToken });
}));

// LinkedIn authentication route
app.get('/auth/linkedin', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  try {
    next();
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
}, passport.authenticate('linkedin'));

// LinkedIn callback route
app.get('/auth/linkedin/callback',
  (req, res, next) => {
    if (!req.query.code) {
    }
    try {
      next();
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  },
  passport.authenticate('linkedin', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      const { accessToken, profile } = req.user;

      if (!accessToken) {
        return res.status(400).json({ error: 'Access token not found' });
      }

      await client.connect();
      const db = client.db(process.env.DB_NAME);
      const usersCollection = db.collection('users');
      const linkedinId = profile.id;
      const firstName = profile.name.givenName;
      const lastName = profile.name.familyName;


      const adAccountsUrl = `https://api.linkedin.com/rest/adAccountUsers?q=authenticatedUser`;
      const adAccountsResponse = await axios.get(adAccountsUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'X-RestLi-Protocol-Version': '2.0.0',
          'LinkedIn-Version': '202406',
        },
      });

      const adAccounts = adAccountsResponse.data.elements.map(account => ({
        accountId: account.account.split(':').pop(),
        role: account.role,
      }));


      const existingUser = await usersCollection.findOne({ linkedinId });
      let user;

      if (existingUser) {
        await usersCollection.updateOne(
          { linkedinId },
          {
            $set: {
              linkedinToken: accessToken,
              firstName,
              lastName,
              lastLogin: new Date(),
              adAccounts,
            },
          }
        );
        user = existingUser;
      } else {
        const newUser = {
          linkedinId,
          linkedinToken: accessToken,
          firstName,
          lastName,
          userId: uuidv4(),
          createdAt: new Date(),
          adAccounts,
        };
        await usersCollection.insertOne(newUser);
        user = newUser;
      }

      const jwtAccessToken = jwt.sign(
        { linkedinId: user.linkedinId, userId: user.userId },
        process.env.LINKEDIN_CLIENT_SECRET,
        { expiresIn: '2h' }
      );

      const refreshToken = jwt.sign(
        { linkedinId: user.linkedinId, userId: user.userId },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );
      await usersCollection.updateOne({ linkedinId }, { $set: { refreshToken } });


      // Set HttpOnly, secure, cross-site cookies for OAuth tokens
      res.cookie('accessToken', jwtAccessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/',
        maxAge: 2 * 60 * 60 * 1000, // 2 hours
      });
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      const frontendUrl = process.env.NODE_ENV === 'production'
        ? process.env.FRONTEND_URL_PROD
        : process.env.FRONTEND_URL_DEV;


      // Redirect to the frontend history page after successful login
      if (!res.headersSent) {
        return res.redirect(`${frontendUrl}/history`);
      }

    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
      }
    }
  }
);

// ─── authenticateToken middleware with proper destructuring ─────────────────
const authenticateToken = async (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return res.status(401).json({ message: 'Access Denied' });
  }

  jwt.verify(token, process.env.LINKEDIN_CLIENT_SECRET, async (err, payload) => {
    if (err) {
      // expired? try to refresh
      if (err.name === 'TokenExpiredError') {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
          return res.status(401).json({ message: 'Refresh token missing' });
        }

        try {
          const tokens = await refreshUserAccessToken(refreshToken);
          if (!tokens?.newAccessToken) {
            return res.status(401).json({ message: 'Could not refresh access token' });
          }
          const { newAccessToken, newRefreshToken } = tokens;

          // Reset both cookies
          res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            path: '/',
            maxAge: 2 * 60 * 60 * 1000,
          });
          res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            path: '/',
            maxAge: 7 * 24 * 60 * 60 * 1000,
          });

          // Verify the new token and continue
          jwt.verify(newAccessToken, process.env.LINKEDIN_CLIENT_SECRET, (err2, freshPayload) => {
            if (err2) {
              return res.status(401).json({ message: 'Token refresh failed' });
            }
            req.user = freshPayload;
            next();
          });
        } catch (refreshErr) {
          console.error('Error during token refresh:', refreshErr);
          return res.status(401).json({ message: 'Could not refresh access token' });
        }
      } else {
        // some other JWT error
        return res.status(401).json({ message: 'Invalid token' });
      }
    } else {
      // token still valid
      req.user = payload;
      next();
    }
  });
};

// API route to fetch the logged-in user's profile
app.get('/api/user-profile', authenticateToken, async (req, res) => {
    try {
      const user = await client.db(process.env.DB_NAME).collection('users').findOne(
        { linkedinId: req.user.linkedinId },
        { projection: { email: 1, firstName: 1, lastName: 1, adAccounts: 1, userId: 1, linkedinId: 1 } }
      );

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        adAccounts: user.adAccounts.map(acc => ({
          id: acc.accountId,
          name: acc.name // Assuming the name of the ad account is fetched
        })),
        userId: user.userId,
        linkedinId: user.linkedinId
      });
    } catch (error) {
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });

app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users');

    await usersCollection.updateOne({ linkedinId: req.user.linkedinId }, { $unset: { refreshToken: '' } });

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/api/refresh-token', async (req, res) => {
  const rt = req.cookies.refreshToken;
  if (!rt) return res.status(401).json({ message: 'Refresh token missing' });

  const tokens = await refreshUserAccessToken(rt);
  if (!tokens) return res.status(403).json({ message: 'Invalid or expired refresh token' });

  // Re-set both cookies
  res.cookie('accessToken', tokens.newAccessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 2 * 60 * 60 * 1000,
    path: '/',
  });
  res.cookie('refreshToken', tokens.newRefreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });

  // Send back the access token too in case you still want to decode it client-side
  res.json({ accessToken: tokens.newAccessToken });
});

app.get('/api/ad-account-name', authenticateToken, async (req, res) => {
  try {
    const user = await client.db(process.env.DB_NAME).collection('users').findOne({ linkedinId: req.user.linkedinId });

    if (!user || !user.adAccounts || user.adAccounts.length === 0) {
      return res.status(404).json({ error: 'Ad accounts not found for this user' });
    }

    const token = user.linkedinToken;

    const adAccountNames = await Promise.all(
      user.adAccounts.map(async (account) => {
        const userAdAccountID = account.accountId.split(':').pop();
        const apiUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}`;

        try {
          const response = await axios.get(apiUrl, {
            headers: {
              Authorization: `Bearer ${token}`,
              'X-RestLi-Protocol-Version': '2.0.0',
              'LinkedIn-Version': '202406',
            },
          });

          // Check if the response has the necessary data
          if (response.data && response.data.name) {
            return { id: account.accountId, name: response.data.name };
          } else {
            console.warn(`No name found for account ${account.accountId}`);
            return { id: account.accountId, name: 'Unknown' };
          }
        } catch (error) {
          // Skip this account if the API returns a 404 error
          if (error.response && error.response.status === 404) {
            return null; // Return null to indicate that this account should be skipped
          } else {
            console.error(`Error fetching name for account ${account.accountId}:`, error.message);
            return { id: account.accountId, name: 'Unknown' };
          }
        }
      })
    );

    // Filter out any null values (accounts that were skipped)
    const validAdAccounts = adAccountNames.filter(account => account !== null);

    // If no valid accounts were found, send a 404 error
    if (validAdAccounts.length === 0) {
      return res.status(404).json({ error: 'No valid ad accounts found for this user' });
    }

    // Update the user document with the fetched account names if needed
    await client.db(process.env.DB_NAME).collection('users').updateOne(
      { linkedinId: req.user.linkedinId },
      { $set: { 'adAccounts.$[elem].name': { $each: validAdAccounts.map(acc => acc.name) } } },
      { arrayFilters: [{ 'elem.accountId': { $in: validAdAccounts.map(acc => acc.id) } }] }
    );

    res.json({ adAccounts: validAdAccounts });
  } catch (error) {
    console.error('Error fetching ad account names:', error);
    res.status(error.response?.status || 500).send('Error fetching ad account names');
  }
});

// New route to fetch LinkedIn chart data
app.get('/api/linkedin/chart-data', authenticateToken, async (req, res) => {
  const { start, end, campaigns, accountId, fields } = req.query;

  if (!accountId) {
    return res.status(400).json({ error: 'Account ID is required' });
  }

  const startDate = new Date(start);
  const endDate = new Date(end);

  // Find the user's LinkedIn token and confirm access to the specified account
  const user = await client.db(process.env.DB_NAME).collection('users').findOne({ linkedinId: req.user.linkedinId });
  const userAdAccountID = user.adAccounts.find(acc => acc.accountId === accountId)?.accountId;

  if (!userAdAccountID) {
    return res.status(400).json({ error: 'Invalid account ID for this user' });
  }

  // Format campaigns array
  let campaignsParam = '';
  if (Array.isArray(campaigns)) {
    const campaignList = campaigns.map(campaignId => `urn%3Ali%3AsponsoredCampaign%3A${campaignId}`).join(',');
    campaignsParam = `&campaigns=List(${campaignList})`;
  }

  // Call LinkedIn API with the specific account ID
  let url = `https://api.linkedin.com/rest/adAnalytics?q=analytics&dateRange=(start:(year:${startDate.getFullYear()},month:${startDate.getMonth() + 1},day:${startDate.getDate()}),end:(year:${endDate.getFullYear()},month:${endDate.getMonth() + 1},day:${endDate.getDate()}))&timeGranularity=DAILY&pivot=CAMPAIGN&accounts=List(urn%3Ali%3AsponsoredAccount%3A${userAdAccountID})&fields=dateRange,${fields}${campaignsParam}`;

  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${user.linkedinToken}`,
        'X-RestLi-Protocol-Version': '2.0.0',
        'LinkedIn-Version': '202406',
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from LinkedIn API:', error.message);
    res.status(500).send(error.message);
  }
});

app.get('/api/get-all-changes', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { adAccountId } = req.query;

  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const userChanges = await db.collection('changes').findOne({ userId });

    if (userChanges) {
      // Fetch URN information from the stored urnInfoMap
      const urnInfoMap = userChanges.urnInfoMap || {};

      // Map human-readable values to URNs in changes
      const mappedChanges = (userChanges.changes[adAccountId] || []).map((change) => {
        const mappedChange = { ...change };
        mappedChange.changes = Object.fromEntries(
          Object.entries(change.changes).map(([key, value]) => {
            if (typeof value === 'string' && urnInfoMap[value]) {
              return [key, urnInfoMap[value]];
            }
            if (typeof value === 'object' && value !== null) {
              return [key, JSON.parse(JSON.stringify(value), (k, v) =>
                (typeof v === 'string' && urnInfoMap[v]) ? urnInfoMap[v] : v
              )];
            }
            return [key, value];
          })
        );
        return mappedChange;
      });

      res.json({ changes: mappedChanges, urnInfoMap });
    } else {
      res.json({ changes: [], urnInfoMap: {} });
    }
  } catch (error) {
    console.error('Error fetching changes from MongoDB:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Add Note Endpoint
app.post('/api/add-note', authenticateToken, async (req, res) => {
  const { accountId, campaignId, newNote } = req.body;
  const userId = req.user.userId;

  if (!accountId || !campaignId || !newNote) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const db = client.db(process.env.DB_NAME);
    const changesCollection = db.collection('changes');
    const noteId = new ObjectId().toHexString(); // Generate a string ID
    const timestamp = new Date().toISOString();

    const result = await changesCollection.updateOne(
      { userId },
      { $push: { [`changes.${accountId}.$[campaignElem].notes`]: { _id: noteId, note: newNote, timestamp } } },
      {
        arrayFilters: [
          { "campaignElem._id": new ObjectId(campaignId) } // Convert campaignId to ObjectId
        ]
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send('Campaign not found');
    }

    res.json({ noteId, timestamp });
  } catch (error) {
    console.error('Error adding note:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Edit Note Endpoint
app.post('/api/edit-note', authenticateToken, async (req, res) => {
  const { accountId, campaignId, noteId, updatedNote } = req.body;
  const userId = req.user.userId;

  if (!accountId || !campaignId || !noteId || !updatedNote) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const db = client.db(process.env.DB_NAME);
    const changesCollection = db.collection('changes');

    const result = await changesCollection.updateOne(
      { userId },
      {
        $set: {
          [`changes.${accountId}.$[campaignElem].notes.$[noteElem].note`]: updatedNote,
          [`changes.${accountId}.$[campaignElem].notes.$[noteElem].timestamp`]: new Date().toISOString()
        }
      },
      {
        arrayFilters: [
          { "campaignElem._id": new ObjectId(campaignId) },
          { $or: [{ "noteElem._id": noteId }, { "noteElem._id": new ObjectId(noteId) }] } // Match both string and ObjectId formats
        ]
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send('Note not found');
    }

    res.send('Note updated successfully');
  } catch (error) {
    console.error('Error updating note:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Delete Note Endpoint
app.post('/api/delete-note', authenticateToken, async (req, res) => {
  const { accountId, campaignId, noteId } = req.body;
  const userId = req.user.userId;

  if (!accountId || !campaignId || !noteId) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const db = client.db(process.env.DB_NAME);
    const changesCollection = db.collection('changes');

    // Attempt to match both string and ObjectId formats for noteId
    const result = await changesCollection.updateOne(
      { userId },
      {
        $pull: {
          [`changes.${accountId}.$[campaignElem].notes`]: {
            $or: [{ _id: noteId }, { _id: new ObjectId(noteId) }]
          }
        }
      },
      {
        arrayFilters: [
          { "campaignElem._id": new ObjectId(campaignId) } // Ensure campaignId is an ObjectId
        ]
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send('Note not found');
    }

    res.send('Note deleted successfully');
  } catch (error) {
    console.error('Error deleting note:', error);
    res.status(500).send('Internal Server Error');
  }
});
// New route to check for changes for a specific user and ad account, with timeZone
app.post('/api/check-for-changes', authenticateToken, async (req, res) => {
  const { userId, adAccountId, timeZone } = req.body;
  if (!userId || !adAccountId) {
    return res.status(400).json({ message: 'User ID and Ad Account ID are required' });
  }

  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users');

    // 1) Load user and get raw LinkedIn OAuth token
    const user = await usersCollection.findOne({ userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const accessToken = user.linkedinToken;
    if (!accessToken) {
      return res.status(401).json({ message: 'LinkedIn token not found' });
    }

    // 2) Make sure the user actually has that ad account
    const account = user.adAccounts.find(acc => acc.accountId === adAccountId);
    if (!account) {
      return res.status(404).json({ message: 'Ad account not found for this user' });
    }

    // 3) Fetch current and LinkedIn campaigns
    const adCampaigns = await fetchAdCampaigns(userId, accessToken, [adAccountId]);
    const currentCampaigns = await fetchCurrentCampaignsFromDB(userId, adAccountId);
    const linkedInCampaigns = adCampaigns[adAccountId]?.campaigns || [];

    const newDifferences = [];
    const urns = [];

    // 4) Compare campaigns
    for (const campaign2 of linkedInCampaigns) {
      // Try to find it in our DB
      const campaign1 = currentCampaigns.find(c => String(c.id) === String(campaign2.id));

      // A) BRAND-NEW campaign: push only the “added” message and skip diffs
      if (!campaign1) {
        newDifferences.push({
          campaignId: campaign2.id,
          campaign:  campaign2.name,
          date:      formatDateWithTimeZone(new Date(), timeZone),
          changes:   { campaignAdded: campaign2.name },
          notes:     campaign2.notes || [],
          _id:       new ObjectId(),
        });
        continue;
      }

      // B) EXISTING campaign: compute detailed diffs
      const changes = findDifferences(campaign1, campaign2, urns);
      if (Object.keys(changes).length > 0) {
        // If campaignGroup changed, fetch its human name
        if (changes.campaignGroup) {
          const groupId = changes.campaignGroup.newValue?.split(':').pop();
          if (groupId) {
            changes.campaignGroup.newValue = await fetchCampaignGroupNameBackend(
              accessToken,
              adAccountId,
              groupId
            );
          }
        }

        newDifferences.push({
          campaignId: campaign2.id,
          campaign:   campaign2.name,
          date:       formatDateWithTimeZone(new Date(), timeZone),
          changes,
          notes:      campaign2.notes || [],
          _id:        campaign1._id || new ObjectId(),
        });
      }
    }

    // 5) Enrich URNs, save everything back to Mongo
    const uniqueUrns = Array.from(new Set(urns.map(JSON.stringify))).map(JSON.parse);
    const urnInfoMap = await fetchUrnInformation(uniqueUrns, accessToken);

    await saveChangesToDB(userId, adAccountId, newDifferences, urnInfoMap);
    await saveAdCampaignsToDB(userId, adCampaigns);

    res.status(200).json({ message: 'Changes checked and saved successfully' });
  } catch (error) {
    console.error('Error in /api/check-for-changes route:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.get('/api/linkedin/linkedin-ad-campaign-groups', authenticateToken, async (req, res) => {
  const { accountId } = req.query;

  if (!accountId) {
    return res.status(400).json({ error: 'Account ID is required' });
  }

  try {
    const user = await client.db(process.env.DB_NAME).collection('users').findOne({ linkedinId: req.user.linkedinId });

    if (!user || !user.linkedinToken) {
      return res.status(404).json({ error: 'User or LinkedIn token not found' });
    }

    const token = user.linkedinToken;
    const userAdAccountID = accountId.split(':').pop();

    const campaignGroupsUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}/adCampaignGroups?q=search&sortOrder=DESCENDING`;
    const campaignsUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}/adCampaigns?q=search&sortOrder=DESCENDING`;

    const [groupsResponse, campaignsResponse] = await Promise.all([
      axios.get(campaignGroupsUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-RestLi-Protocol-Version': '2.0.0',
          'LinkedIn-Version': '202406',
        },
      }),
      axios.get(campaignsUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-RestLi-Protocol-Version': '2.0.0',
          'LinkedIn-Version': '202406',
        },
      }),
    ]);

    // Log the campaigns response data
    const campaigns = campaignsResponse.data.elements || [];
    const campaignGroups = groupsResponse.data.elements.map(group => ({
      ...group,
      campaigns: campaigns.filter(campaign => {
        // Extract the numeric ID from the URN string
        const campaignGroupId = campaign.campaignGroup.split(':').pop();
        return campaignGroupId === String(group.id); // Compare as strings
      }),
      visible: false,
    }));

    res.json(campaignGroups);
  } catch (error) {
    console.error('Error fetching ad campaign groups or campaigns:', error);
    res.status(500).send('Error fetching ad campaign groups or campaigns');
  }
});

// Save a preset
app.post('/api/save-preset', authenticateToken, async (req, res) => {
  const { name, filters, searchText, selectedCampaigns, selectedCampaignIds } = req.body;
  const userId = req.user.userId;

  if (!name || !filters) {
    return res.status(400).json({ message: 'Preset name and filters are required' });
  }

  try {
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users');

    const result = await usersCollection.updateOne(
      { userId },
      {
        $push: {
          presets: {
            name,
            filters,
            searchText,
            selectedCampaigns: selectedCampaigns || [], // Save selected campaigns
            selectedCampaignIds: selectedCampaignIds || [] // Save selected campaign IDs
          }
        }
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Preset saved successfully' });
  } catch (error) {
    console.error('Error saving preset:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Retrieve presets
app.get('/api/get-presets', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    await client.connect(); // Ensure the MongoDB client is connected
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users'); // Define usersCollection

    const user = await usersCollection.findOne({ userId }, { projection: { presets: 1 } });

    if (!user || !user.presets) {
      return res.status(404).json({ message: 'No presets found' });
    }

    res.status(200).json(user.presets);
  } catch (error) {
    console.error('Error retrieving presets:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Delete a preset
app.delete('/api/delete-preset', authenticateToken, async (req, res) => {
  const { name } = req.body;
  const userId = req.user.userId;

  if (!name) {
    return res.status(400).json({ message: 'Preset name is required' });
  }

  try {
    await client.connect(); // Ensure the MongoDB client is connected
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users');

    const result = await usersCollection.updateOne(
      { userId },
      { $pull: { presets: { name } } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Preset not found' });
    }

    res.status(200).json({ message: 'Preset deleted successfully' });
  } catch (error) {
    console.error('Error deleting preset:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from Express backend!' });
});

// Move static middleware to the end, after all dynamic routes
if (process.env.NODE_ENV === 'production') {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  app.use(express.static(path.join(__dirname, '../public')));

  // Default route to serve the frontend
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});

// The main function that runs in the cron job
async function checkForChangesForAllUsers() {
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const usersCollection = db.collection('users');

    // Fetch all users from the database
    const users = await usersCollection.find({}).toArray();

    for (const user of users) {
      const { userId, adAccounts } = user;

      // Verify and refresh token if needed
      const accessToken = await verifyAndRefreshTokenIfNeeded(user);
      if (!accessToken) {
        console.warn(`User ${userId} does not have a valid token, skipping...`);
        continue;
      }

      // Extract all the accountIds for this user
      const accountIds = adAccounts.map((a) => a.accountId);

      // 1. Fetch updated ad campaigns & creatives
      const adCampaigns = await fetchAdCampaigns(userId, accessToken, accountIds);

      // 2. Compare campaigns for each ad account and save differences
      for (const account of adAccounts) {
        const accountId = account.accountId;
        try {
          // Fetch current campaigns from DB
          const currentCampaigns = await fetchCurrentCampaignsFromDB(userId, accountId);

          // Get LinkedIn campaigns from adCampaigns object
          const linkedInCampaigns = adCampaigns[accountId]?.campaigns || [];

          const newDifferences = [];
          const urns = []; // Collect URNs here

          // Compare campaigns
          for (const campaign2 of linkedInCampaigns) {
            const campaign1 = currentCampaigns.find((c) => String(c.id) === String(campaign2.id));
            const changes = findDifferences(campaign1 || {}, campaign2, urns);

            if (Object.keys(changes).length > 0) {
              if (changes.campaignGroup) {
                const groupId = changes.campaignGroup.newValue?.split(':').pop();
                if (groupId) {
                  changes.campaignGroup.newValue = await fetchCampaignGroupNameBackend(accessToken, accountId, groupId);
                }
              }

              const difference = {
                campaign: campaign2.name,
                date: formatDate(new Date()),
                changes,
                notes: campaign2.notes || [],
                _id: campaign1 && campaign1._id ? new ObjectId(campaign1._id) : new ObjectId(),
              };
              newDifferences.push(difference);
            } else if (!campaign1) {
              // New campaign
              newDifferences.push({
                campaign: campaign2.name,
                date: formatDate(new Date()),
                changes: { campaignAdded: campaign2.name },
                notes: [],
                _id: new ObjectId(),
              });
            }
          }

          // Fetch URN info if needed
          const uniqueUrns = Array.from(new Set(urns.map(JSON.stringify))).map(JSON.parse);
          const urnInfoMap = await fetchUrnInformation(uniqueUrns, accessToken);
          newDifferences.forEach((d) => (d.urnInfoMap = urnInfoMap));

          // Save the new differences
          await saveChangesToDB(userId, accountId, newDifferences);

        } catch (error) {
          console.error(`Error in checking changes for user ${userId}, account ${accountId}:`, error);
        }
      }

      // 3. After processing all accounts, save the updated adCampaigns back to DB
      await saveAdCampaignsToDB(userId, adCampaigns);
    }
  } catch (error) {
    console.error('Error in checkForChangesForAllUsers:', error);
  }
}

// Save Ad Campaigns to DB
async function saveAdCampaignsToDB(userId, adCampaigns) {
  const db = client.db(process.env.DB_NAME);
  await db.collection('adCampaigns').updateOne(
    { userId },
    { $set: { adCampaigns } },
    { upsert: true }
  );
}

// Save changes to DB
async function saveChangesToDB(userId, adAccountId, changes, urnInfoMap) {
  if (!adAccountId) {
    console.error("Error: adAccountId is undefined.");
    return;
  }

  const db = client.db(process.env.DB_NAME);
  const collection = db.collection('changes');

  const changesWithIds = changes.map(change => ({
    ...change,
    _id: change._id ? new ObjectId(change._id) : new ObjectId(),
  }));

  const existingUserChanges = await collection.findOne({ userId });

  if (existingUserChanges) {
    const existingAdAccountChanges = existingUserChanges.changes[adAccountId] || [];

    const uniqueChanges = changesWithIds.filter(newChange =>
      !existingAdAccountChanges.some(existingChange =>
        (existingChange._id && existingChange._id.equals(newChange._id)) ||
        (existingChange.campaign === newChange.campaign &&
          existingChange.date === newChange.date &&
          JSON.stringify(existingChange.changes) === JSON.stringify(newChange.changes))
      )
    );

    if (uniqueChanges.length > 0) {
      await collection.updateOne(
        { userId },
        {
          $push: { [`changes.${adAccountId}`]: { $each: uniqueChanges } },
          $set: { urnInfoMap: { ...existingUserChanges.urnInfoMap, ...urnInfoMap } }
        }
      );
    }
  } else {
    await collection.insertOne({
      userId,
      changes: { [adAccountId]: changesWithIds },
      urnInfoMap
    });
  }
}

async function fetchAdCampaigns(userId, accessToken, accountIds) {
  const db = client.db(process.env.DB_NAME);
  const existingAdCampaignsDoc = await db.collection('adCampaigns').findOne({ userId });
  const adCampaigns = {};

  for (const accountId of accountIds) {
    const userAdAccountID = accountId.split(':').pop();
    const token = accessToken;

    const campaignsApiUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}/adCampaigns?q=search&sortOrder=DESCENDING`;

    let campaignsWithCreatives = existingAdCampaignsDoc?.adCampaigns?.[accountId]?.campaigns || [];

    try {
      // Fetch ad campaigns
      const response = await axios.get(campaignsApiUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-RestLi-Protocol-Version': '2.0.0',
          'LinkedIn-Version': '202406',
        },
      });

      // Fetch creatives for each campaign
      campaignsWithCreatives = await Promise.all(
        response.data.elements.map(async (campaign) => {
          try {
            const campaignId = 'urn:li:sponsoredCampaign:' + campaign.id; 
            const creativesApiUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}/creatives?q=criteria&campaigns=List(${encodeURIComponent(campaignId)})&fields=id,isServing,content`;

            const creativesResponse = await axios.get(creativesApiUrl, {
              headers: {
                Authorization: `Bearer ${token}`,
                'X-RestLi-Protocol-Version': '2.0.0',
                'LinkedIn-Version': '202406',
              },
            });

            // Process each creative
            campaign.creatives = await Promise.all(
              creativesResponse.data.elements.map(async (creative) => {
                if (creative.content?.textAd?.headline) {
                  creative.name = creative.content.textAd.headline;
                } else if (creative.content?.reference) {
                  const referenceId = creative.content.reference;
                  try {
                    const referenceApiUrl = `https://api.linkedin.com/rest/posts/${encodeURIComponent(referenceId)}`;
                    const referenceResponse = await axios.get(referenceApiUrl, {
                      headers: {
                        Authorization: `Bearer ${token}`,
                        'X-RestLi-Protocol-Version': '2.0.0',
                        'LinkedIn-Version': '202307',
                      },
                    });
                    creative.name = referenceResponse.data.adContext?.dscName || 'Unnamed Creative';
                  } catch (error) {
                    console.error(`Error fetching reference details for creative ${creative.id}:`, error);
                    creative.name = 'Unnamed Creative';
                  }
                } else {
                  creative.name = 'Unnamed Creative';
                }

                return creative;
              })
            );

            return campaign;
          } catch (error) {
            console.error(`Error fetching creatives for campaign ${campaign.id}:`, error);
            campaign.creatives = [];
            return campaign;
          }
        })
      );
    } catch (error) {
      // Check if it's a 401/403 due to invalid token
      if (error.response && (error.response.status === 401 || error.response.status === 403)) {
        const newAccessToken = await refreshUserAccessToken(user.refreshToken);
        if (newAccessToken) {
          // Update the user's accessToken in DB if not already done in refreshUserAccessToken
          await db.collection('users').updateOne({ userId: user.userId }, { $set: { accessToken: newAccessToken } });
          // Retry your request with the newAccessToken
        } else {
          console.error(`Failed to refresh token for user ${user.userId}`);
          // Skip this user or handle accordingly
        }
      } else {
        // Some other error
        console.error('Some other error occurred:', error.message);
      }
      console.error(`Error fetching ad campaigns for accountId ${accountId}:`, error);
      // If error, fallback to existing data
      campaignsWithCreatives = existingAdCampaignsDoc?.adCampaigns?.[accountId]?.campaigns || [];
    }

    // Store fetched data or fallback data
    adCampaigns[accountId] = {
      campaigns: campaignsWithCreatives,
      campaignGroups: existingAdCampaignsDoc?.adCampaigns?.[accountId]?.campaignGroups || [],
      budget: existingAdCampaignsDoc?.adCampaigns?.[accountId]?.budget || null,
    };
  }

  // Ensure all user's accounts have data
  const userDoc = await db.collection('users').findOne({ userId });
  userDoc.adAccounts.forEach((account) => {
    const id = account.accountId;
    if (!adCampaigns.hasOwnProperty(id)) {
      adCampaigns[id] = {
        campaigns: existingAdCampaignsDoc?.adCampaigns?.[id]?.campaigns || [],
        campaignGroups: existingAdCampaignsDoc?.adCampaigns?.[id]?.campaignGroups || [],
        budget: existingAdCampaignsDoc?.adCampaigns?.[id]?.budget || null,
      };
    }
  });

  return adCampaigns;
}

// A helper function to verify token validity and refresh if needed
async function verifyAndRefreshTokenIfNeeded(user) {
  if (!user.accessToken) {
    console.warn(`Access token missing for user ${user.userId}`);
    return null;
  }

  // Attempt a simple LinkedIn API call to verify token validity. 
  // For example, calling the "me" endpoint if available, or any cheap endpoint.
  const testUrl = 'https://api.linkedin.com/v2/me'; // This endpoint returns user details and requires a valid token

  try {
    const test = await axios.get(testUrl, {
      headers: {
        Authorization: `Bearer ${user.accessToken}`,
        'X-RestLi-Protocol-Version': '2.0.0',
        'LinkedIn-Version': '202306', // or appropriate version
      },
      timeout: 5000 // just a small timeout
    });
    // If we get here, the token is valid
    return user.accessToken;
  } catch (error) {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      // Token is invalid, attempt a refresh
      const newAccessToken = await refreshUserAccessToken(user.refreshToken);
      if (newAccessToken) {
        // Update DB with newAccessToken
        const db = client.db(process.env.DB_NAME);
        await db.collection('users').updateOne({ userId: user.userId }, { $set: { accessToken: newAccessToken } });
        return newAccessToken;
      } else {
        console.error(`Failed to refresh token for user ${user.userId}`);
        return null;
      }
    } else {
      // Some other error occurred
      console.error('Error verifying token:', error.message);
      return null;
    }
  }
}

async function refreshUserAccessToken(refreshToken) {
  if (!refreshToken) {
    console.error('No refresh token provided');
    return null;
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const userId = decoded.userId;

    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const user = await db.collection('users').findOne({ userId });

    if (!user) {
      console.error('Refresh token user not found');
      return null;
    }

    // Generate a new refresh token to replace the old one
    const newRefreshToken = jwt.sign(
      { userId: user.userId, linkedinId: user.linkedinId },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    const newAccessToken = jwt.sign(
      { userId: user.userId, linkedinId: user.linkedinId },
      process.env.LINKEDIN_CLIENT_SECRET,
      { expiresIn: '2h' }
    );

    // Save only the new refresh token in the database (do NOT overwrite linkedinToken)
    await db.collection('users').updateOne(
      { userId },
      { $set: { refreshToken: newRefreshToken } }
    );

    return { newAccessToken, newRefreshToken };
  } catch (error) {
    console.error('Error refreshing token:', error.message);
    return null;
  }
}

const findDifferences = (obj1, obj2, urns = [], urnInfoMap = {}) => {
  const diffs = {};

  for (const key in obj1) {
    if (key === 'changeAuditStamps' || key === 'version' || key === 'campaignGroup') continue;

    if (Object.prototype.hasOwnProperty.call(obj2, key)) {
      const val1 = obj1[key];
      const val2 = obj2[key];

      // Handle amount key
      if (key === 'amount' && val1 !== val2) {
        diffs[key] = {
          oldValue: `$${val1}`,
          newValue: `$${val2}`,
        };
        continue;
      }

      // Handle targeting criteria (added/removed logic)
      if (key.startsWith('urn:li:adTargetingFacet:') && Array.isArray(val1) && Array.isArray(val2)) {
        const oldSet = new Set(val1);
        const newSet = new Set(val2);

        const removedItems = [...oldSet].filter((x) => !newSet.has(x));
        const addedItems = [...newSet].filter((x) => !oldSet.has(x));

        if (removedItems.length > 0 || addedItems.length > 0) {
          diffs[key] = {
            added: addedItems.map((v) => replaceUrnWithInfo(v, urnInfoMap)),
            removed: removedItems.map((v) => replaceUrnWithInfo(v, urnInfoMap)),
          };
          removedItems.forEach((item) => extractUrnsFromValue(item, urns));
          addedItems.forEach((item) => extractUrnsFromValue(item, urns));
        }
      }
      // Handle creatives
      else if (key === 'creatives' && Array.isArray(val1) && Array.isArray(val2)) {
        const creativeDiffs = [];

        // Map existing creatives by ID for easy comparison
        const creativeMap1 = val1.reduce((map, creative) => {
          map[creative.id] = creative;
          return map;
        }, {});
        const creativeMap2 = val2.reduce((map, creative) => {
          map[creative.id] = creative;
          return map;
        }, {});

        // Check for changes in `isServing` property and content
        for (const creativeId in creativeMap1) {
          if (creativeMap2[creativeId]) {
            const creative1 = creativeMap1[creativeId];
            const creative2 = creativeMap2[creativeId];

            if (creative1.isServing !== creative2.isServing) {
              const name = creative2.name || 'Unnamed Creative';
              const newState = creative2.isServing;
              creativeDiffs.push({
                name,
                isServing: newState ? 'Set to: true' : 'Set to: false',
              });
            }

            if (JSON.stringify(creative1.content) !== JSON.stringify(creative2.content)) {
              creativeDiffs.push({
                name: creative2.name || 'Unnamed Creative',
                content: {
                  oldValue: creative1.content,
                  newValue: creative2.content,
                },
              });
            }
          }
        }

        // Check for added creatives
        for (const creativeId in creativeMap2) {
          if (!creativeMap1[creativeId]) {
            creativeDiffs.push({
              name: creativeMap2[creativeId].name || 'Unnamed Creative',
              added: true,
            });
          }
        }

        // Check for removed creatives
        for (const creativeId in creativeMap1) {
          if (!creativeMap2[creativeId]) {
            creativeDiffs.push({
              name: creativeMap1[creativeId].name || 'Unnamed Creative',
              removed: true,
            });
          }
        }

        if (creativeDiffs.length > 0) {
          diffs[key] = creativeDiffs;
        }
      }
      // Recurse for nested objects
      else if (
        typeof val1 === 'object' &&
        typeof val2 === 'object' &&
        !(Array.isArray(val1) && Array.isArray(val2) && key.startsWith('urn:li:adTargetingFacet:'))
      ) {
        const nestedDiffs = findDifferences(val1, val2, urns, urnInfoMap);
        if (Object.keys(nestedDiffs).length > 0) {
          diffs[key] = nestedDiffs;
        }
      } else if (JSON.stringify(val1) !== JSON.stringify(val2)) {
        diffs[key] = {
          oldValue: replaceUrnWithInfo(val1, urnInfoMap),
          newValue: replaceUrnWithInfo(val2, urnInfoMap),
        };
        extractUrnsFromValue(val1, urns);
        extractUrnsFromValue(val2, urns);
      }
    } else {
      diffs[key] = {
        oldValue: replaceUrnWithInfo(obj1[key], urnInfoMap),
        newValue: null,
      };
      extractUrnsFromValue(obj1[key], urns);
    }
  }

  for (const key in obj2) {
    if (key === 'version') continue;

    if (!Object.prototype.hasOwnProperty.call(obj1, key)) {
      if (key === 'amount') {
        diffs[key] = {
          oldValue: null,
          newValue: `$${obj2[key]}`,
        };
      } else {
        diffs[key] = {
          oldValue: null,
          newValue: replaceUrnWithInfo(obj2[key], urnInfoMap),
        };
      }
      extractUrnsFromValue(obj2[key], urns);
    }
  }

  return diffs;
};

// Backend function to fetch Campaign Group Name
async function fetchCampaignGroupNameBackend(token, accountId, groupId) {
  const userAdAccountID = accountId.split(':').pop();
  const apiUrl = `https://api.linkedin.com/rest/adAccounts/${userAdAccountID}/adCampaignGroups/${groupId}`;

  try {
    const response = await axios.get(apiUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        'X-RestLi-Protocol-Version': '2.0.0',
        'LinkedIn-Version': '202406',
      },
    });
    return response.data?.name || 'Unknown';
  } catch (error) {
    console.error('Error fetching campaign group name:', error.message);
    return 'Unknown';
  }
}

// Fetch current campaigns from our database
async function fetchCurrentCampaignsFromDB(userId, accountId) {
  const db = client.db(process.env.DB_NAME);
  const adCampaignsDoc = await db.collection('adCampaigns').findOne({ userId });
  return adCampaignsDoc?.adCampaigns?.[accountId]?.campaigns || [];
}

// Function to fetch URN Information
async function fetchUrnInformation(urns, token) {
  // Similar logic to the front-end version, but now call the backend endpoints directly
  // Actually, since this is backend, you can call LinkedIn APIs directly here as well.
  // For each urnType/urnId, call your LinkedIn API logic and build up `urnInfoMap`.
  const urnInfoMap = {};

  for (const { urnType, urnId } of urns) {
    // build URL or handle logic similarly as on front end
    let name = await fetchUrnInfoBackend(token, urnType, urnId);
    urnInfoMap[`urn:li:${urnType}:${urnId}`] = name;
  }

  return urnInfoMap;
}

// Backend version of fetchUrnInfo
async function fetchUrnInfoBackend(token, urnType, urnId) {
  // Call the LinkedIn API to get targeting entity or adSegment data
  // Similar to the front-end logic, but no `document.cookie`, just use `token` directly
  let endpoint = `/api/linkedin/targeting-entities`; 
  // Actually call LinkedIn API directly here, since you're on server side
  // For example:
  if (urnType === 'adSegment') {
    const apiUrl = `https://api.linkedin.com/rest/adSegments/${urnId}`;
    try {
      const res = await axios.get(apiUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-RestLi-Protocol-Version': '2.0.0',
          'LinkedIn-Version': '202406',
        },
      });
      return res.data.name || `Unknown (${urnType})`;
    } catch {
      return `Error (${urnType})`;
    }
  } else {
    const apiUrl = `https://api.linkedin.com/rest/adTargetingEntities?q=urns&urns=urn:li:${urnType}:${urnId}`;
    try {
      const res = await axios.get(apiUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'LinkedIn-Version': '202406',
        },
      });
      const element = res.data.elements?.[0];
      return element?.name || `Unknown (${urnType})`;
    } catch {
      return `Error (${urnType})`;
    }
  }
}

const replaceUrnWithInfo = (value, urnInfoMap) => {
  if (typeof value === 'string') {
    return urnInfoMap[value] || value; // Replace URN with mapped info or keep the original
  }
  return value;
};

const formatDate = (date) => {
  const options = { year: 'numeric', month: '2-digit', day: '2-digit' };
  return new Date(date).toLocaleDateString('en-US', options);
};


const extractUrns = (value, urns = []) => {
  const urnPattern = /urn:li:([a-zA-Z]+):([^\s]+)/g;
  let match;
  while ((match = urnPattern.exec(value)) !== null) {
    urns.push({ urnType: match[1], urnId: match[2] });
  }
};

const extractUrnsFromValue = (value, urns) => {
  if (typeof value === 'string') {
    extractUrns(value, urns);
  } else if (Array.isArray(value)) {
    value.forEach((item) => extractUrnsFromValue(item, urns));
  } else if (typeof value === 'object' && value !== null) {
    for (const key in value) {
      extractUrnsFromValue(value[key], urns);
    }
  }
};

// Now, in your cron setup:
cron.schedule('0 23 * * *', async () => { // runs every day at 2am for example
  console.log('Checking for changes for all users...');
  await checkForChangesForAllUsers();
  console.log('Done checking for changes for all users');
});