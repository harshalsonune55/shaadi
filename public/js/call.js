const socket = io();
const roomId = "<%= receiver.phone %>"; // or combined id

let localStream;
let peerConnection;

const iceServers = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" }
  ]
};

async function startCall() {
  localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });

  document.getElementById("localVideo").srcObject = localStream;

  peerConnection = new RTCPeerConnection(iceServers);

  localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

  peerConnection.ontrack = e => {
    document.getElementById("remoteVideo").srcObject = e.streams[0];
  };

  peerConnection.onicecandidate = e => {
    if (e.candidate) {
      socket.emit("ice_candidate", { roomId, candidate: e.candidate });
    }
  };

  socket.emit("join_call", { roomId });

  const offer = await peerConnection.createOffer();
  await peerConnection.setLocalDescription(offer);

  socket.emit("offer", { roomId, offer });
}

socket.on("offer", async offer => {
  await peerConnection.setRemoteDescription(offer);
  const answer = await peerConnection.createAnswer();
  await peerConnection.setLocalDescription(answer);
  socket.emit("answer", { roomId, answer });
});

socket.on("answer", async answer => {
  await peerConnection.setRemoteDescription(answer);
});

socket.on("ice_candidate", async candidate => {
  await peerConnection.addIceCandidate(candidate);
});

function endCall() {
  socket.emit("end_call", { roomId });
  peerConnection.close();
}

let isMuted = false;
let isCameraOff = false;

function toggleMute() {
  if (!localStream) return;
  localStream.getAudioTracks().forEach(track => {
    track.enabled = isMuted;
  });
  isMuted = !isMuted;
  document.getElementById("muteBtn").innerText = isMuted ? "🔊 Unmute" : "🔇 Mute";
}

function toggleCamera() {
  if (!localStream) return;
  localStream.getVideoTracks().forEach(track => {
    track.enabled = isCameraOff;
  });
  isCameraOff = !isCameraOff;
  document.getElementById("cameraBtn").innerText = isCameraOff ? "📷 Camera On" : "📷 Camera Off";
}

