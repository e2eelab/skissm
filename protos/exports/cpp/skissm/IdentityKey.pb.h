// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/IdentityKey.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fIdentityKey_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fIdentityKey_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3019000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3019004 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include "skissm/KeyPair.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fIdentityKey_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fIdentityKey_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[1]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fIdentityKey_2eproto;
namespace skissm {
class IdentityKey;
struct IdentityKeyDefaultTypeInternal;
extern IdentityKeyDefaultTypeInternal _IdentityKey_default_instance_;
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> ::skissm::IdentityKey* Arena::CreateMaybeMessage<::skissm::IdentityKey>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace skissm {

// ===================================================================

class IdentityKey final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:skissm.IdentityKey) */ {
 public:
  inline IdentityKey() : IdentityKey(nullptr) {}
  ~IdentityKey() override;
  explicit constexpr IdentityKey(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  IdentityKey(const IdentityKey& from);
  IdentityKey(IdentityKey&& from) noexcept
    : IdentityKey() {
    *this = ::std::move(from);
  }

  inline IdentityKey& operator=(const IdentityKey& from) {
    CopyFrom(from);
    return *this;
  }
  inline IdentityKey& operator=(IdentityKey&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const IdentityKey& default_instance() {
    return *internal_default_instance();
  }
  static inline const IdentityKey* internal_default_instance() {
    return reinterpret_cast<const IdentityKey*>(
               &_IdentityKey_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(IdentityKey& a, IdentityKey& b) {
    a.Swap(&b);
  }
  inline void Swap(IdentityKey* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(IdentityKey* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  IdentityKey* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<IdentityKey>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const IdentityKey& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const IdentityKey& from);
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to, const ::PROTOBUF_NAMESPACE_ID::Message& from);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(IdentityKey* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "skissm.IdentityKey";
  }
  protected:
  explicit IdentityKey(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kAsymKeyPairFieldNumber = 1,
    kSignKeyPairFieldNumber = 2,
  };
  // .skissm.KeyPair asym_key_pair = 1;
  bool has_asym_key_pair() const;
  private:
  bool _internal_has_asym_key_pair() const;
  public:
  void clear_asym_key_pair();
  const ::skissm::KeyPair& asym_key_pair() const;
  PROTOBUF_NODISCARD ::skissm::KeyPair* release_asym_key_pair();
  ::skissm::KeyPair* mutable_asym_key_pair();
  void set_allocated_asym_key_pair(::skissm::KeyPair* asym_key_pair);
  private:
  const ::skissm::KeyPair& _internal_asym_key_pair() const;
  ::skissm::KeyPair* _internal_mutable_asym_key_pair();
  public:
  void unsafe_arena_set_allocated_asym_key_pair(
      ::skissm::KeyPair* asym_key_pair);
  ::skissm::KeyPair* unsafe_arena_release_asym_key_pair();

  // .skissm.KeyPair sign_key_pair = 2;
  bool has_sign_key_pair() const;
  private:
  bool _internal_has_sign_key_pair() const;
  public:
  void clear_sign_key_pair();
  const ::skissm::KeyPair& sign_key_pair() const;
  PROTOBUF_NODISCARD ::skissm::KeyPair* release_sign_key_pair();
  ::skissm::KeyPair* mutable_sign_key_pair();
  void set_allocated_sign_key_pair(::skissm::KeyPair* sign_key_pair);
  private:
  const ::skissm::KeyPair& _internal_sign_key_pair() const;
  ::skissm::KeyPair* _internal_mutable_sign_key_pair();
  public:
  void unsafe_arena_set_allocated_sign_key_pair(
      ::skissm::KeyPair* sign_key_pair);
  ::skissm::KeyPair* unsafe_arena_release_sign_key_pair();

  // @@protoc_insertion_point(class_scope:skissm.IdentityKey)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::skissm::KeyPair* asym_key_pair_;
  ::skissm::KeyPair* sign_key_pair_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fIdentityKey_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// IdentityKey

// .skissm.KeyPair asym_key_pair = 1;
inline bool IdentityKey::_internal_has_asym_key_pair() const {
  return this != internal_default_instance() && asym_key_pair_ != nullptr;
}
inline bool IdentityKey::has_asym_key_pair() const {
  return _internal_has_asym_key_pair();
}
inline const ::skissm::KeyPair& IdentityKey::_internal_asym_key_pair() const {
  const ::skissm::KeyPair* p = asym_key_pair_;
  return p != nullptr ? *p : reinterpret_cast<const ::skissm::KeyPair&>(
      ::skissm::_KeyPair_default_instance_);
}
inline const ::skissm::KeyPair& IdentityKey::asym_key_pair() const {
  // @@protoc_insertion_point(field_get:skissm.IdentityKey.asym_key_pair)
  return _internal_asym_key_pair();
}
inline void IdentityKey::unsafe_arena_set_allocated_asym_key_pair(
    ::skissm::KeyPair* asym_key_pair) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(asym_key_pair_);
  }
  asym_key_pair_ = asym_key_pair;
  if (asym_key_pair) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:skissm.IdentityKey.asym_key_pair)
}
inline ::skissm::KeyPair* IdentityKey::release_asym_key_pair() {
  
  ::skissm::KeyPair* temp = asym_key_pair_;
  asym_key_pair_ = nullptr;
#ifdef PROTOBUF_FORCE_COPY_IN_RELEASE
  auto* old =  reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(temp);
  temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  if (GetArenaForAllocation() == nullptr) { delete old; }
#else  // PROTOBUF_FORCE_COPY_IN_RELEASE
  if (GetArenaForAllocation() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
#endif  // !PROTOBUF_FORCE_COPY_IN_RELEASE
  return temp;
}
inline ::skissm::KeyPair* IdentityKey::unsafe_arena_release_asym_key_pair() {
  // @@protoc_insertion_point(field_release:skissm.IdentityKey.asym_key_pair)
  
  ::skissm::KeyPair* temp = asym_key_pair_;
  asym_key_pair_ = nullptr;
  return temp;
}
inline ::skissm::KeyPair* IdentityKey::_internal_mutable_asym_key_pair() {
  
  if (asym_key_pair_ == nullptr) {
    auto* p = CreateMaybeMessage<::skissm::KeyPair>(GetArenaForAllocation());
    asym_key_pair_ = p;
  }
  return asym_key_pair_;
}
inline ::skissm::KeyPair* IdentityKey::mutable_asym_key_pair() {
  ::skissm::KeyPair* _msg = _internal_mutable_asym_key_pair();
  // @@protoc_insertion_point(field_mutable:skissm.IdentityKey.asym_key_pair)
  return _msg;
}
inline void IdentityKey::set_allocated_asym_key_pair(::skissm::KeyPair* asym_key_pair) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(asym_key_pair_);
  }
  if (asym_key_pair) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(asym_key_pair));
    if (message_arena != submessage_arena) {
      asym_key_pair = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, asym_key_pair, submessage_arena);
    }
    
  } else {
    
  }
  asym_key_pair_ = asym_key_pair;
  // @@protoc_insertion_point(field_set_allocated:skissm.IdentityKey.asym_key_pair)
}

// .skissm.KeyPair sign_key_pair = 2;
inline bool IdentityKey::_internal_has_sign_key_pair() const {
  return this != internal_default_instance() && sign_key_pair_ != nullptr;
}
inline bool IdentityKey::has_sign_key_pair() const {
  return _internal_has_sign_key_pair();
}
inline const ::skissm::KeyPair& IdentityKey::_internal_sign_key_pair() const {
  const ::skissm::KeyPair* p = sign_key_pair_;
  return p != nullptr ? *p : reinterpret_cast<const ::skissm::KeyPair&>(
      ::skissm::_KeyPair_default_instance_);
}
inline const ::skissm::KeyPair& IdentityKey::sign_key_pair() const {
  // @@protoc_insertion_point(field_get:skissm.IdentityKey.sign_key_pair)
  return _internal_sign_key_pair();
}
inline void IdentityKey::unsafe_arena_set_allocated_sign_key_pair(
    ::skissm::KeyPair* sign_key_pair) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(sign_key_pair_);
  }
  sign_key_pair_ = sign_key_pair;
  if (sign_key_pair) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:skissm.IdentityKey.sign_key_pair)
}
inline ::skissm::KeyPair* IdentityKey::release_sign_key_pair() {
  
  ::skissm::KeyPair* temp = sign_key_pair_;
  sign_key_pair_ = nullptr;
#ifdef PROTOBUF_FORCE_COPY_IN_RELEASE
  auto* old =  reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(temp);
  temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  if (GetArenaForAllocation() == nullptr) { delete old; }
#else  // PROTOBUF_FORCE_COPY_IN_RELEASE
  if (GetArenaForAllocation() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
#endif  // !PROTOBUF_FORCE_COPY_IN_RELEASE
  return temp;
}
inline ::skissm::KeyPair* IdentityKey::unsafe_arena_release_sign_key_pair() {
  // @@protoc_insertion_point(field_release:skissm.IdentityKey.sign_key_pair)
  
  ::skissm::KeyPair* temp = sign_key_pair_;
  sign_key_pair_ = nullptr;
  return temp;
}
inline ::skissm::KeyPair* IdentityKey::_internal_mutable_sign_key_pair() {
  
  if (sign_key_pair_ == nullptr) {
    auto* p = CreateMaybeMessage<::skissm::KeyPair>(GetArenaForAllocation());
    sign_key_pair_ = p;
  }
  return sign_key_pair_;
}
inline ::skissm::KeyPair* IdentityKey::mutable_sign_key_pair() {
  ::skissm::KeyPair* _msg = _internal_mutable_sign_key_pair();
  // @@protoc_insertion_point(field_mutable:skissm.IdentityKey.sign_key_pair)
  return _msg;
}
inline void IdentityKey::set_allocated_sign_key_pair(::skissm::KeyPair* sign_key_pair) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(sign_key_pair_);
  }
  if (sign_key_pair) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(sign_key_pair));
    if (message_arena != submessage_arena) {
      sign_key_pair = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, sign_key_pair, submessage_arena);
    }
    
  } else {
    
  }
  sign_key_pair_ = sign_key_pair;
  // @@protoc_insertion_point(field_set_allocated:skissm.IdentityKey.sign_key_pair)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace skissm

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fIdentityKey_2eproto