// Provider + core hooks
export {
  QeetIDProvider,
  useAuth,
  useUser,
  useQeetIDClient,
  useAppearance,
  type QeetIDProviderProps,
} from "./context.js";

// Gate components + redirect buttons + account control
export {
  SignedIn,
  SignedOut,
  SignInButton,
  SignUpButton,
  SignOutButton,
  UserButton,
  type AuthButtonProps,
  type UserButtonProps,
} from "./components.js";

// Branded "Sign in with Qeet" buttons
export {
  SignInWithQeet,
  SignUpWithQeet,
  ContinueWithQeet,
  type QeetAuthButtonProps,
} from "./qeet-button.js";

// Headless hooks (embedded mode — requires apiUrl on <QeetIDProvider>)
export { useSignIn, type UseSignInReturn, type SignInStatus } from "./hooks/useSignIn.js";
export { useSignUp, type UseSignUpReturn, type SignUpStatus } from "./hooks/useSignUp.js";
export { useSession, type UseSessionReturn } from "./hooks/useSession.js";
export {
  useOrganization,
  type UseOrganizationReturn,
  type Organization,
} from "./hooks/useOrganization.js";
export { useOrganizationList, type UseOrganizationListReturn } from "./hooks/useOrganizationList.js";
export { usePasskeys, type UsePasskeysReturn } from "./hooks/usePasskeys.js";
export { useMfa, type UseMfaReturn, type MfaStatus } from "./hooks/useMfa.js";

// Prebuilt embedded components (embedded mode — requires apiUrl on <QeetIDProvider>)
export { SignIn, type SignInProps } from "./embedded/SignIn.js";
export { SignUp, type SignUpProps } from "./embedded/SignUp.js";
export { UserProfile, type UserProfileProps } from "./embedded/UserProfile.js";
export {
  OrganizationSwitcher,
  type OrganizationSwitcherProps,
} from "./embedded/OrganizationSwitcher.js";
export {
  OrganizationProfile,
  type OrganizationProfileProps,
} from "./embedded/OrganizationProfile.js";
export {
  CreateOrganization,
  type CreateOrganizationProps,
} from "./embedded/CreateOrganization.js";

// Appearance API types
export type { Appearance, AppearanceVariables, AppearanceElements, AppearanceTheme } from "./embedded/types.js";

// Core state types
export type { QeetIDUser, QeetIDState } from "./types.js";
